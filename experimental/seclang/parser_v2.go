// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package seclang provides an experimental ANTLR4-based SecLang parser
// that uses the crslang type system to parse SecLang into structured types,
// then converts those types into Coraza's internal representation.
//
// This implementation uses the ANTLR4 grammar from:
// https://github.com/coreruleset/seclang_parser
// And the crslang types from:
// https://github.com/coreruleset/crslang
package seclang

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/antlr4-go/antlr/v4"
	"github.com/coreruleset/crslang/listener"
	crstypes "github.com/coreruleset/crslang/types"
	seclang_parser "github.com/coreruleset/seclang_parser/parser"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	actionsmod "github.com/corazawaf/coraza/v3/internal/actions"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/operators"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// maxIncludeRecursion prevents DoS via circular includes
const maxIncludeRecursion = 100

// ParserState holds mutable state that persists across directive parsing
type ParserState struct {
	// Default actions per phase (raw action strings)
	RuleDefaultActions    []string
	HasRuleDefaultActions bool

	// Disabled features
	DisabledRuleActions   []string
	DisabledRuleOperators []string

	// Datasets for file-based operators
	Datasets map[string][]string

	// Current location for error reporting
	CurrentFile string
	CurrentDir  string
	CurrentLine int

	// Working directory
	WorkingDir string

	// Filesystem root
	Root fs.FS

	// IgnoreRuleCompilationErrors, if true, ignores rule compilation errors
	IgnoreRuleCompilationErrors bool
}

// Parser uses the crslang listener to parse SecLang into structured types,
// then converts those types into Coraza's internal representation.
type Parser struct {
	waf          *corazawaf.WAF
	root         fs.FS
	currentFile  string
	currentDir   string
	includeCount int

	state *ParserState
}

// NewParser creates a new ANTLR4-based SecLang parser that uses crslang's listener
func NewParser(waf *corazawaf.WAF) *Parser {
	return &Parser{
		waf:  waf,
		root: nil,
		state: &ParserState{
			Datasets: make(map[string][]string),
		},
	}
}

// SetRoot sets the filesystem root for this parser
func (p *Parser) SetRoot(root fs.FS) {
	p.root = root
	p.state.Root = root
}

// FromFile imports directives from a file
func (p *Parser) FromFile(profilePath string) error {
	originalDir := p.currentDir

	var files []string
	if strings.Contains(profilePath, "*") {
		fsys := p.root
		if fsys == nil {
			fsys = &osFS{}
		}

		var err error
		files, err = fs.Glob(fsys, profilePath)
		if err != nil {
			return fmt.Errorf("failed to glob: %w", err)
		}

		if len(files) == 0 {
			p.waf.Logger.Warn().
				Str("pattern", profilePath).
				Msg("empty glob result")
		}
	} else {
		files = append(files, profilePath)
	}

	for _, filePath := range files {
		filePath = strings.TrimSpace(filePath)

		if !strings.HasPrefix(filePath, "/") {
			filePath = filepath.Join(p.currentDir, filePath)
		}

		p.currentFile = filePath
		lastDir := p.currentDir
		p.currentDir = filepath.Dir(filePath)
		p.state.CurrentFile = filePath
		p.state.CurrentDir = p.currentDir

		fsys := p.root
		if fsys == nil {
			fsys = &osFS{}
		}

		data, err := fs.ReadFile(fsys, filePath)
		if err != nil {
			p.currentDir = originalDir
			p.currentFile = ""
			return fmt.Errorf("failed to read file %s: %w", filePath, err)
		}

		if err := p.parseString(string(data)); err != nil {
			p.currentDir = originalDir
			p.currentFile = ""
			return fmt.Errorf("failed to parse file %s: %w", filePath, err)
		}

		p.currentDir = lastDir
	}

	p.currentDir = originalDir
	p.currentFile = ""

	return nil
}

// FromString imports directives from a string
func (p *Parser) FromString(data string) error {
	oldCurrentFile := p.currentFile
	p.currentFile = "_inline_"
	p.state.CurrentFile = "_inline_"

	err := p.parseString(data)

	p.currentFile = oldCurrentFile
	p.state.CurrentFile = oldCurrentFile

	return err
}

// parseString parses SecLang configuration using ANTLR4 and crslang's listener
func (p *Parser) parseString(data string) error {
	input := antlr.NewInputStream(data)

	lexer := seclang_parser.NewSecLangLexer(input)
	lexerErrorListener := newErrorListener()
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(lexerErrorListener)

	stream := antlr.NewCommonTokenStream(lexer, 0)

	secLangParser := seclang_parser.NewSecLangParser(stream)
	parserErrorListener := newErrorListener()
	secLangParser.RemoveErrorListeners()
	secLangParser.AddErrorListener(parserErrorListener)

	tree := secLangParser.Configuration()

	allErrors := append(lexerErrorListener.errors, parserErrorListener.errors...)
	if len(allErrors) > 0 {
		return fmt.Errorf("parse errors: %v", allErrors)
	}

	// Use crslang's listener to extract structured data
	crsListener := &listener.ExtendedSeclangParserListener{
		BaseSecLangParserListener: &seclang_parser.BaseSecLangParserListener{},
	}
	antlr.ParseTreeWalkerDefault.Walk(crsListener, tree)

	// Convert crslang types to Coraza WAF configuration.
	// After tree walking, all directives are in ConfigurationList.DirectiveList
	// (ExitConfiguration copies DirectiveList into ConfigurationList).
	converter := newTypeConverter(p.waf, p.state)
	for _, dl := range crsListener.ConfigurationList.DirectiveList {
		if err := converter.convertDirectives(&dl); err != nil {
			return err
		}
	}

	return nil
}

// osFS is a simple wrapper that implements fs.FS for the root filesystem
type osFS struct{}

func (osFS) Open(name string) (fs.File, error) {
	if strings.HasPrefix(name, "/") {
		return os.DirFS("/").Open(strings.TrimPrefix(name, "/"))
	}
	return os.DirFS(".").Open(name)
}

// errorListener collects syntax errors during parsing
type errorListener struct {
	*antlr.DefaultErrorListener
	errors []error
}

func newErrorListener() *errorListener {
	return &errorListener{
		DefaultErrorListener: antlr.NewDefaultErrorListener(),
		errors:               make([]error, 0),
	}
}

func (el *errorListener) SyntaxError(
	_ antlr.Recognizer,
	_ interface{},
	line, column int,
	msg string,
	_ antlr.RecognitionException,
) {
	el.errors = append(el.errors, fmt.Errorf("syntax error at line %d:%d: %s", line, column, msg))
}

// ruleAction mirrors internal/seclang.ruleAction for action processing
type ruleAction struct {
	Key   string
	Value string
	Atype plugintypes.ActionType
	F     plugintypes.Action
}

// typeConverter converts crslang types to Coraza's internal representation
type typeConverter struct {
	waf    *corazawaf.WAF
	state  *ParserState
	errors []error
}

func newTypeConverter(waf *corazawaf.WAF, state *ParserState) *typeConverter {
	return &typeConverter{
		waf:   waf,
		state: state,
	}
}

// convertDirectives converts a list of crslang directives to Coraza configuration
func (c *typeConverter) convertDirectives(directiveList *crstypes.DirectiveList) error {
	if directiveList == nil {
		return nil
	}

	for _, directive := range directiveList.Directives {
		if err := c.convertDirective(directive); err != nil {
			if c.state.IgnoreRuleCompilationErrors {
				c.waf.Logger.Debug().
					Err(err).
					Msg("Ignoring rule compilation error")
				continue
			}
			return err
		}
	}

	// Handle SecMarker which is stored as the Marker field, not in Directives
	if directiveList.Marker.Name != "" {
		if err := c.convertConfigDirective(&directiveList.Marker); err != nil {
			return err
		}
	}

	return nil
}

// convertDirective converts a single crslang directive to Coraza configuration
func (c *typeConverter) convertDirective(directive crstypes.SeclangDirective) error {
	switch d := directive.(type) {
	case *crstypes.SecRule:
		return c.convertSecRule(d)
	case *crstypes.SecAction:
		return c.convertSecAction(d)
	case crstypes.ConfigurationDirective:
		return c.convertConfigDirective(&d)
	case *crstypes.ConfigurationDirective:
		return c.convertConfigDirective(d)
	case crstypes.DefaultAction:
		return c.convertDefaultAction(&d)
	case *crstypes.DefaultAction:
		return c.convertDefaultAction(d)
	case crstypes.RemoveRuleDirective:
		return c.convertRemoveRule(&d)
	case *crstypes.RemoveRuleDirective:
		return c.convertRemoveRule(d)
	case *crstypes.UpdateTargetDirective:
		return c.convertUpdateTarget(d)
	case *crstypes.UpdateActionDirective:
		return c.convertUpdateActions(d)
	case crstypes.CommentMetadata:
		// Comments are ignored
		return nil
	case *crstypes.CommentDirective:
		// Comments are ignored
		return nil
	case crstypes.CommentDirective:
		// Comments are ignored
		return nil
	default:
		c.waf.Logger.Warn().
			Str("type", fmt.Sprintf("%T", directive)).
			Msg("unsupported directive type")
		return nil
	}
}

// convertConfigDirective converts a configuration directive
func (c *typeConverter) convertConfigDirective(config *crstypes.ConfigurationDirective) error {
	name := string(config.Name)
	value := config.Parameter

	switch config.Name {
	case crstypes.SecRuleEngine:
		engine, err := types.ParseRuleEngineStatus(value)
		if err != nil {
			return err
		}
		c.waf.RuleEngine = engine
	case crstypes.SecRequestBodyAccess:
		b, err := parseBoolean(strings.ToLower(value))
		if err != nil {
			return err
		}
		c.waf.RequestBodyAccess = b
	case crstypes.SecResponseBodyAccess:
		b, err := parseBoolean(strings.ToLower(value))
		if err != nil {
			return err
		}
		c.waf.ResponseBodyAccess = b
	case crstypes.SecRequestBodyLimit:
		limit, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		c.waf.RequestBodyLimit = limit
	case crstypes.SecResponseBodyLimit:
		limit, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		c.waf.ResponseBodyLimit = limit
	case crstypes.SecComponentSignature:
		c.waf.ComponentNames = append(c.waf.ComponentNames, value)
	case crstypes.SecMarker:
		return c.convertSecMarker(value)
	default:
		c.waf.Logger.Debug().
			Str("directive", name).
			Msg("configuration directive not yet implemented")
	}

	return nil
}

// convertSecMarker creates a marker rule
func (c *typeConverter) convertSecMarker(name string) error {
	rule := corazawaf.NewRule()
	rule.Raw_ = fmt.Sprintf("SecMarker %s", name)
	rule.SecMark_ = name
	rule.ID_ = 0
	rule.LogID_ = "0"
	rule.Phase_ = 0
	rule.Line_ = c.state.CurrentLine
	rule.File_ = c.state.CurrentFile
	return c.waf.Rules.Add(rule)
}

// convertSecRule converts a crslang SecRule to a Coraza rule
func (c *typeConverter) convertSecRule(secRule *crstypes.SecRule) error {
	rule := corazawaf.NewRule()

	// 1. Convert variables and collections
	if err := c.addVariables(rule, secRule.Variables, secRule.Collections); err != nil {
		return fmt.Errorf("failed to convert variables: %w", err)
	}

	// 2. Convert operator
	if err := c.setOperator(rule, secRule.Operator); err != nil {
		return fmt.Errorf("failed to convert operator: %w", err)
	}

	// 3. Process actions (metadata first, then merge with defaults, then apply rest)
	if err := c.applyActions(rule, secRule.GetActions(), secRule.GetTransformations(), secRule.GetMetadata()); err != nil {
		return fmt.Errorf("failed to convert actions: %w", err)
	}

	// Set file/line metadata
	rule.File_ = c.state.CurrentFile
	rule.Line_ = c.state.CurrentLine

	// Handle chain rules
	if secRule.ChainedRule != nil {
		rule.HasChain = true
	}

	// Check if this rule should be chained to a parent
	if parent := getLastRuleExpectingChain(c.waf); parent != nil {
		rule.ParentID_ = parent.ID_
		rule.LogID_ = parent.LogID_
		lastChain := parent
		for lastChain.Chain != nil {
			lastChain = lastChain.Chain
		}
		rule.Phase_ = 0
		lastChain.Chain = rule
		parent.Raw_ += " \n" + secRule.ToSeclang()
	} else {
		rule.Raw_ = secRule.ToSeclang()
		if err := c.waf.Rules.Add(rule); err != nil {
			return err
		}
	}

	// Recursively convert chained rules
	if secRule.ChainedRule != nil {
		return c.convertChainableDirective(secRule.ChainedRule)
	}

	return nil
}

// convertChainableDirective converts a chained directive (can be SecRule, SecAction, etc.)
func (c *typeConverter) convertChainableDirective(directive crstypes.ChainableDirective) error {
	switch d := directive.(type) {
	case *crstypes.SecRule:
		return c.convertSecRule(d)
	case *crstypes.SecAction:
		return c.convertSecAction(d)
	default:
		return fmt.Errorf("unsupported chained directive type: %T", directive)
	}
}

// convertSecAction converts a crslang SecAction to a Coraza rule
func (c *typeConverter) convertSecAction(secAction *crstypes.SecAction) error {
	rule := corazawaf.NewRule()

	// SecAction has no variables or operator
	if err := c.applyActions(rule, secAction.GetActions(), secAction.GetTransformations(), secAction.GetMetadata()); err != nil {
		return fmt.Errorf("failed to convert actions: %w", err)
	}

	rule.File_ = c.state.CurrentFile
	rule.Line_ = c.state.CurrentLine

	if secAction.ChainedRule != nil {
		rule.HasChain = true
	}

	if parent := getLastRuleExpectingChain(c.waf); parent != nil {
		rule.ParentID_ = parent.ID_
		rule.LogID_ = parent.LogID_
		lastChain := parent
		for lastChain.Chain != nil {
			lastChain = lastChain.Chain
		}
		rule.Phase_ = 0
		lastChain.Chain = rule
		parent.Raw_ += " \n" + secAction.ToSeclang()
	} else {
		rule.Raw_ = secAction.ToSeclang()
		if err := c.waf.Rules.Add(rule); err != nil {
			return err
		}
	}

	if secAction.ChainedRule != nil {
		return c.convertChainableDirective(secAction.ChainedRule)
	}

	return nil
}

// convertDefaultAction stores default actions in parser state
func (c *typeConverter) convertDefaultAction(da *crstypes.DefaultAction) error {
	// Convert back to seclang string for compatibility with existing ParseDefaultActions
	seclangStr := da.ToSeclang()
	// Strip "SecDefaultAction " prefix and quotes
	seclangStr = strings.TrimPrefix(seclangStr, "SecDefaultAction ")
	seclangStr = utils.MaybeRemoveQuotes(seclangStr)

	c.state.RuleDefaultActions = append(c.state.RuleDefaultActions, seclangStr)
	c.state.HasRuleDefaultActions = true
	return nil
}

// convertRemoveRule removes rules by ID, tag, or msg
func (c *typeConverter) convertRemoveRule(remove *crstypes.RemoveRuleDirective) error {
	for _, id := range remove.Ids {
		c.waf.Rules.DeleteByID(id)
	}
	for _, idRange := range remove.IdRanges {
		c.waf.Rules.DeleteByRange(idRange.Start, idRange.End)
	}
	for _, tag := range remove.Tags {
		c.waf.Rules.DeleteByTag(tag)
	}
	for _, msg := range remove.Msgs {
		c.waf.Rules.DeleteByMsg(msg)
	}
	return nil
}

// convertUpdateTarget modifies variables on existing rules
func (c *typeConverter) convertUpdateTarget(update *crstypes.UpdateTargetDirective) error {
	// Build variable string from crslang types for each target rule
	varStr := c.buildVariableString(update.Variables, update.Collections)

	for _, id := range update.Ids {
		rule := c.waf.Rules.FindByID(id)
		if rule == nil {
			c.waf.Logger.Warn().
				Int("rule_id", id).
				Msg("SecRuleUpdateTargetById: rule not found")
			continue
		}
		if err := c.addVariablesFromString(rule, varStr); err != nil {
			return fmt.Errorf("failed to update target for rule %d: %w", id, err)
		}
	}
	return nil
}

// convertUpdateActions modifies actions on existing rules
func (c *typeConverter) convertUpdateActions(update *crstypes.UpdateActionDirective) error {
	rule := c.waf.Rules.FindByID(update.Id)
	if rule == nil {
		c.waf.Logger.Warn().
			Int("rule_id", update.Id).
			Msg("SecRuleUpdateActionById: rule not found")
		return nil
	}

	// Build actions from the update directive
	actions, err := c.buildRuleActions(update.GetActions())
	if err != nil {
		return fmt.Errorf("failed to build actions for update: %w", err)
	}

	// Check for disruptive action replacement
	hasDisruptive := false
	for _, a := range actions {
		if a.Atype == plugintypes.ActionTypeDisruptive {
			hasDisruptive = true
			break
		}
	}
	if hasDisruptive {
		rule.ClearDisruptiveActions()
	}

	// Apply metadata actions first
	for _, a := range actions {
		if a.Atype == plugintypes.ActionTypeMetadata {
			if err := a.F.Init(rule, a.Value); err != nil {
				return fmt.Errorf("failed to init metadata action %s: %w", a.Key, err)
			}
		}
	}

	// Apply non-metadata actions
	for _, a := range actions {
		if a.Atype == plugintypes.ActionTypeMetadata {
			continue
		}
		if err := a.F.Init(rule, a.Value); err != nil {
			return err
		}
		if err := rule.AddAction(a.Key, a.F); err != nil {
			return err
		}
	}

	return nil
}

// addVariables converts crslang variables and collections and adds them to a rule
func (c *typeConverter) addVariables(rule *corazawaf.Rule, vars []crstypes.Variable, cols []crstypes.Collection) error {
	// Process simple variables
	for _, v := range vars {
		varName := v.Name.String()
		rv, err := variables.Parse(varName)
		if err != nil {
			return fmt.Errorf("unknown variable %q: %w", varName, err)
		}
		if v.Excluded {
			if err := rule.AddVariableNegation(rv, ""); err != nil {
				return err
			}
		} else {
			if err := rule.AddVariable(rv, "", false); err != nil {
				return err
			}
		}
	}

	// Process collections (variables with selectors)
	for _, col := range cols {
		colName := col.Name.String()
		rv, err := variables.Parse(colName)
		if err != nil {
			return fmt.Errorf("unknown collection %q: %w", colName, err)
		}

		if len(col.Arguments) == 0 && len(col.Excluded) == 0 {
			// Collection without specific key (e.g., just ARGS)
			if err := rule.AddVariable(rv, "", col.Count); err != nil {
				return err
			}
		} else {
			// Collection with specific keys (e.g., ARGS:username)
			for _, arg := range col.Arguments {
				if err := rule.AddVariable(rv, arg, col.Count); err != nil {
					return err
				}
			}
		}

		// Handle exclusions
		for _, exc := range col.Excluded {
			if err := rule.AddVariableNegation(rv, exc); err != nil {
				return err
			}
		}
	}

	return nil
}

// setOperator converts a crslang operator and sets it on the rule
func (c *typeConverter) setOperator(rule *corazawaf.Rule, op crstypes.Operator) error {
	opName := op.Name.String()

	opts := plugintypes.OperatorOptions{
		Arguments: op.Value,
		Path: []string{
			c.state.CurrentDir,
		},
		Root:     c.state.Root,
		Datasets: c.state.Datasets,
	}

	if wd := c.state.WorkingDir; wd != "" {
		opts.Path = append(opts.Path, wd)
	}

	// Check if operator is disabled
	if utils.InSlice(opName, c.state.DisabledRuleOperators) {
		return fmt.Errorf("%s rule operator is disabled", opName)
	}

	opfn, err := operators.Get(opName, opts)
	if err != nil {
		return fmt.Errorf("operator %q: %w", opName, err)
	}

	funcName := "@" + opName
	if op.Negate {
		funcName = "!" + funcName
	}
	rule.SetOperator(opfn, funcName, op.Value)
	return nil
}

// applyActions processes crslang actions and metadata, and applies them to a rule.
// This follows the same pattern as internal/seclang/rule_parser.go applyParsedActions.
func (c *typeConverter) applyActions(rule *corazawaf.Rule, seclangActions *crstypes.SeclangActions, trans crstypes.Transformations, metadata crstypes.Metadata) error {
	// Build ruleAction list from crslang actions
	actions, err := c.buildRuleActions(seclangActions)
	if err != nil {
		return err
	}

	// Build metadata actions from crslang Metadata (id, phase, msg, severity, etc.)
	metaActions, err := c.buildMetadataActions(metadata)
	if err != nil {
		return err
	}
	actions = append(metaActions, actions...)

	// Add transformation actions
	for _, t := range trans.Transformations {
		tName := t.String()
		f, getErr := actionsmod.Get("t")
		if getErr != nil {
			return getErr
		}
		actions = append(actions, ruleAction{
			Key:   "t",
			Value: tName,
			Atype: f.Type(),
			F:     f,
		})
	}

	// Check for disabled actions
	for _, a := range actions {
		if utils.InSlice(a.Key, c.state.DisabledRuleActions) {
			return fmt.Errorf("%s rule action is disabled", a.Key)
		}
	}

	// Execute metadata actions first (id, phase, msg, severity, etc.)
	for _, a := range actions {
		if a.Atype == plugintypes.ActionTypeMetadata {
			if err := a.F.Init(rule, a.Value); err != nil {
				return fmt.Errorf("failed to init action %s: %s", a.Key, err.Error())
			}
		}
	}

	// Parse and merge with default actions
	phase := rule.Phase_
	defaults, err := c.getDefaultActions(phase)
	if err != nil {
		return err
	}
	if defaults != nil {
		actions = mergeActions(actions, defaults)
	}

	// Execute non-metadata actions
	for _, a := range actions {
		if a.Atype == plugintypes.ActionTypeMetadata {
			continue
		}
		if err := a.F.Init(rule, a.Value); err != nil {
			return err
		}
		if err := rule.AddAction(a.Key, a.F); err != nil {
			return err
		}
	}

	return nil
}

// buildMetadataActions converts crslang metadata into ruleAction entries for metadata actions.
// crslang stores id, phase, msg, severity, etc. in the Metadata struct, not in Actions.
func (c *typeConverter) buildMetadataActions(metadata crstypes.Metadata) ([]ruleAction, error) {
	if metadata == nil {
		return nil, nil
	}

	var actions []ruleAction

	// Build metadata action pairs based on the concrete type
	switch m := metadata.(type) {
	case *crstypes.SecRuleMetadata:
		if m.Id != 0 {
			a, err := c.makeMetadataAction("id", strconv.Itoa(m.Id))
			if err != nil {
				return nil, err
			}
			actions = append(actions, a)
		}
		if m.Phase != "" {
			a, err := c.makeMetadataAction("phase", m.Phase)
			if err != nil {
				return nil, err
			}
			actions = append(actions, a)
		}
		if m.Msg != "" {
			a, err := c.makeMetadataAction("msg", m.Msg)
			if err != nil {
				return nil, err
			}
			actions = append(actions, a)
		}
		if m.Severity != "" {
			a, err := c.makeMetadataAction("severity", m.Severity)
			if err != nil {
				return nil, err
			}
			actions = append(actions, a)
		}
		for _, tag := range m.Tags {
			a, err := c.makeMetadataAction("tag", tag)
			if err != nil {
				return nil, err
			}
			actions = append(actions, a)
		}
		if m.Rev != "" {
			a, err := c.makeMetadataAction("rev", m.Rev)
			if err != nil {
				return nil, err
			}
			actions = append(actions, a)
		}
		if m.Ver != "" {
			a, err := c.makeMetadataAction("ver", m.Ver)
			if err != nil {
				return nil, err
			}
			actions = append(actions, a)
		}
		if m.Maturity != "" {
			a, err := c.makeMetadataAction("maturity", m.Maturity)
			if err != nil {
				return nil, err
			}
			actions = append(actions, a)
		}
	case *crstypes.OnlyPhaseMetadata:
		if m.Phase != "" {
			a, err := c.makeMetadataAction("phase", m.Phase)
			if err != nil {
				return nil, err
			}
			actions = append(actions, a)
		}
	}

	return actions, nil
}

func (c *typeConverter) makeMetadataAction(key, value string) (ruleAction, error) {
	f, err := actionsmod.Get(key)
	if err != nil {
		return ruleAction{}, fmt.Errorf("metadata action %q: %w", key, err)
	}
	return ruleAction{
		Key:   key,
		Value: value,
		Atype: f.Type(),
		F:     f,
	}, nil
}

// buildRuleActions converts crslang SeclangActions into ruleAction slice
func (c *typeConverter) buildRuleActions(seclangActions *crstypes.SeclangActions) ([]ruleAction, error) {
	if seclangActions == nil {
		return nil, nil
	}

	var actions []ruleAction
	disruptiveIdx := -1

	// Disruptive action
	if seclangActions.DisruptiveAction != nil {
		a, err := c.actionToRuleAction(seclangActions.DisruptiveAction)
		if err != nil {
			return nil, err
		}
		disruptiveIdx = len(actions)
		actions = append(actions, a)
	}

	// Non-disruptive actions
	for _, action := range seclangActions.NonDisruptiveActions {
		a, err := c.actionToRuleAction(action)
		if err != nil {
			return nil, err
		}
		// Handle multiple disruptive actions (last one wins)
		if a.Atype == plugintypes.ActionTypeDisruptive {
			if disruptiveIdx != -1 {
				actions[disruptiveIdx] = a
			} else {
				disruptiveIdx = len(actions)
				actions = append(actions, a)
			}
		} else {
			actions = append(actions, a)
		}
	}

	// Flow actions
	for _, action := range seclangActions.FlowActions {
		a, err := c.actionToRuleAction(action)
		if err != nil {
			return nil, err
		}
		actions = append(actions, a)
	}

	// Data actions
	for _, action := range seclangActions.DataActions {
		a, err := c.actionToRuleAction(action)
		if err != nil {
			return nil, err
		}
		actions = append(actions, a)
	}

	return actions, nil
}

// actionToRuleAction converts a single crslang Action to a ruleAction
func (c *typeConverter) actionToRuleAction(action crstypes.Action) (ruleAction, error) {
	key := action.GetKey()

	// Handle setvar specially - crslang's GetAllParams() returns "setvar:TX.key=value"
	// but Coraza's setvar Init expects just "TX.key=value"
	if sv, ok := action.(crstypes.SetvarAction); ok {
		params := sv.GetAllParams()
		var result []ruleAction
		for _, param := range params {
			// Strip the "setvar:" prefix that GetAllParams includes
			param = strings.TrimPrefix(param, "setvar:")
			f, err := actionsmod.Get("setvar")
			if err != nil {
				return ruleAction{}, err
			}
			result = append(result, ruleAction{
				Key:   "setvar",
				Value: param,
				Atype: f.Type(),
				F:     f,
			})
		}
		if len(result) > 0 {
			return result[0], nil
		}
		return ruleAction{}, fmt.Errorf("empty setvar action")
	}

	// Extract value from action
	var value string
	if awp, ok := action.(crstypes.ActionWithParam); ok {
		value = awp.GetParam()
	}

	f, err := actionsmod.Get(key)
	if err != nil {
		return ruleAction{}, fmt.Errorf("unknown action %q: %w", key, err)
	}

	return ruleAction{
		Key:   key,
		Value: value,
		Atype: f.Type(),
		F:     f,
	}, nil
}

// getDefaultActions returns the parsed default actions for the given phase
func (c *typeConverter) getDefaultActions(phase types.RulePhase) ([]ruleAction, error) {
	defaultActions := make(map[types.RulePhase][]ruleAction)

	if c.state.HasRuleDefaultActions {
		for _, da := range c.state.RuleDefaultActions {
			act, err := parseActions(da)
			if err != nil {
				return nil, err
			}
			daPhase := types.RulePhase(0)
			for _, a := range act {
				if a.Key == "phase" {
					daPhase, err = types.ParseRulePhase(a.Value)
					if err != nil {
						return nil, err
					}
				}
			}
			if daPhase != 0 {
				defaultActions[daPhase] = act
			}
		}
	}

	// If no default actions for phase 2, use hardcoded defaults
	if defaultActions[types.PhaseRequestBody] == nil {
		act, err := parseActions("phase:2,log,auditlog,pass")
		if err != nil {
			return nil, err
		}
		defaultActions[types.PhaseRequestBody] = act
	}

	return defaultActions[phase], nil
}

// parseActions parses a comma-separated action string into ruleAction slice.
// This replicates the logic from internal/seclang/rule_parser.go parseActions.
func parseActions(actions string) ([]ruleAction, error) {
	var res []ruleAction
	disruptiveActionIndex := -1

	beforeKey := -1
	afterKey := -1
	inQuotes := false

	for i := 1; i < len(actions); i++ {
		c := actions[i]
		if actions[i-1] == '\\' {
			continue
		}
		if c == '\'' {
			inQuotes = !inQuotes
			continue
		}
		if inQuotes {
			continue
		}
		switch c {
		case ':':
			if afterKey != -1 {
				continue
			}
			afterKey = i
		case ',':
			var val string
			if afterKey == -1 {
				afterKey = i
			} else {
				val = actions[afterKey+1 : i]
			}
			var err error
			res, disruptiveActionIndex, err = appendRuleAction(res, actions[beforeKey+1:afterKey], val, disruptiveActionIndex)
			if err != nil {
				return nil, err
			}
			beforeKey = i
			afterKey = -1
		}
	}

	var val string
	if afterKey == -1 {
		afterKey = len(actions)
	} else {
		val = actions[afterKey+1:]
	}
	var err error
	res, _, err = appendRuleAction(res, actions[beforeKey+1:afterKey], val, disruptiveActionIndex)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func appendRuleAction(res []ruleAction, key string, val string, disruptiveActionIndex int) ([]ruleAction, int, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	val = strings.TrimSpace(val)
	val = utils.MaybeRemoveQuotes(val)
	f, err := actionsmod.Get(key)
	if err != nil {
		return res, -1, err
	}
	if f.Type() == plugintypes.ActionTypeDisruptive && disruptiveActionIndex != -1 {
		res[disruptiveActionIndex] = ruleAction{
			Key:   key,
			Value: val,
			F:     f,
			Atype: f.Type(),
		}
	} else {
		if f.Type() == plugintypes.ActionTypeDisruptive {
			disruptiveActionIndex = len(res)
		}
		res = append(res, ruleAction{
			Key:   key,
			Value: val,
			F:     f,
			Atype: f.Type(),
		})
	}
	return res, disruptiveActionIndex, nil
}

// mergeActions merges rule actions with default actions.
// Replicates internal/seclang/rule_parser.go mergeActions.
func mergeActions(origin []ruleAction, defaults []ruleAction) []ruleAction {
	var res []ruleAction
	var da ruleAction
	for _, action := range defaults {
		if action.Atype == plugintypes.ActionTypeDisruptive {
			da = action
			continue
		}
		if action.Atype == plugintypes.ActionTypeMetadata {
			continue
		}
		res = append(res, action)
	}
	hasDa := false
	for _, action := range origin {
		if action.Atype == plugintypes.ActionTypeDisruptive {
			if action.Key != "block" {
				hasDa = true
				res = append(res, action)
			}
		} else {
			res = append(res, action)
		}
	}
	if !hasDa {
		res = append(res, da)
	}
	return res
}

// buildVariableString builds a pipe-separated variable string from crslang types
func (c *typeConverter) buildVariableString(vars []crstypes.Variable, cols []crstypes.Collection) string {
	var parts []string
	for _, v := range vars {
		name := v.Name.String()
		if v.Excluded {
			name = "!" + name
		}
		parts = append(parts, name)
	}
	for _, col := range cols {
		name := col.Name.String()
		prefix := ""
		if col.Count {
			prefix = "&"
		}
		if len(col.Arguments) == 0 {
			parts = append(parts, prefix+name)
		} else {
			for _, arg := range col.Arguments {
				parts = append(parts, prefix+name+":"+arg)
			}
		}
		for _, exc := range col.Excluded {
			parts = append(parts, "!"+name+":"+exc)
		}
	}
	return strings.Join(parts, "|")
}

// addVariablesFromString parses a variable string and adds to a rule
// Used by update target directive
func (c *typeConverter) addVariablesFromString(rule *corazawaf.Rule, vars string) error {
	// Parse the variable string character by character (same as RuleParser.ParseVariables)
	// For simplicity, we split on | and process each
	for _, part := range strings.Split(vars, "|") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		isNegation := false
		isCount := false

		if strings.HasPrefix(part, "!") {
			isNegation = true
			part = part[1:]
		}
		if strings.HasPrefix(part, "&") {
			isCount = true
			part = part[1:]
		}

		varName, key, _ := strings.Cut(part, ":")

		rv, err := variables.Parse(varName)
		if err != nil {
			return fmt.Errorf("unknown variable %q: %w", varName, err)
		}

		if isNegation {
			if err := rule.AddVariableNegation(rv, key); err != nil {
				return err
			}
		} else {
			if err := rule.AddVariable(rv, key, isCount); err != nil {
				return err
			}
		}
	}
	return nil
}

// getLastRuleExpectingChain finds the last rule in the WAF that expects a chain
func getLastRuleExpectingChain(w *corazawaf.WAF) *corazawaf.Rule {
	rules := w.Rules.GetRules()
	if len(rules) == 0 {
		return nil
	}

	lastRule := &rules[len(rules)-1]
	parent := lastRule
	for parent.Chain != nil {
		parent = parent.Chain
	}
	if parent.HasChain && parent.Chain == nil {
		return lastRule
	}

	return nil
}

func parseBoolean(s string) (bool, error) {
	switch s {
	case "on":
		return true, nil
	case "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q, expected on/off", s)
	}
}
