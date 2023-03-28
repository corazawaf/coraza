// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"errors"
	"fmt"
	"strings"

	actionsmod "github.com/corazawaf/coraza/v3/internal/actions"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/operators"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

var defaultActionsPhase2 = "phase:2,log,auditlog,pass"

type ruleAction struct {
	Key   string
	Value string
	Atype rules.ActionType
	F     rules.Action
}

// RuleParser is used to programatically create new rules using seclang formatted strings
type RuleParser struct {
	rule           *corazawaf.Rule
	defaultActions map[types.RulePhase][]ruleAction
	options        RuleOptions
}

// ParseVariables parses variables from a string and transforms it into
// variables, variable negations and variable counters.
// Multiple separated variables: VARIABLE1|VARIABLE2|VARIABLE3
// Variable count: &VARIABLE1
// Variable key negation: REQUEST_HEADERS|!REQUEST_HEADERS:user-agent
func (p *RuleParser) ParseVariables(vars string) error {

	// 0 = variable name
	// 1 = key
	// 2 = inside regex
	// 3 = inside xpath
	curr := 0
	isNegation := false
	isCount := false
	var curVar []byte
	var curKey []byte
	isEscaped := false
	isquoted := false
	for i := 0; i < len(vars); i++ {
		c := vars[i]
		if (c == '|' && curr != 2) || i+1 >= len(vars) || (curr == 2 && c == '/' && !isEscaped) {
			// if next variable or end
			// if regex we ignore |
			// we wont support pipe for xpath, maybe later
			if c != '|' {
				// we don't want to miss the last character
				if curr == 0 {
					curVar = append(curVar, c)
				} else if curr != 2 && c != '/' {
					// we don't want the last slash if it's a regex
					curKey = append(curKey, c)
				}
			}
			v, err := variables.Parse(string(curVar))
			if err != nil {
				return err
			}
			// fmt.Printf("(PREVIOUS %s) %s:%s (%t %t)\n", vars, curvar, curkey, iscount, isnegation)
			if isquoted {
				// if it is quoted we remove the last quote
				if len(vars) <= i+1 || vars[i+1] != '\'' {
					if vars[i] != '\'' {
						// TODO fix here
						return fmt.Errorf("unclosed quote: " + string(curKey))
					}
				}
				// we skip one additional character
				i += 2
				isquoted = false
			} else if curr == 2 {
				i++
			}

			key := string(curKey)
			if curr == 2 {
				// we are inside a regex
				key = fmt.Sprintf("/%s/", key)
			}
			if isNegation {
				err = p.rule.AddVariableNegation(v, key)
			} else {
				err = p.rule.AddVariable(v, key, isCount)
			}
			if err != nil {
				return err
			}
			curVar = nil
			curKey = nil
			isCount = false
			isNegation = false
			curr = 0
			continue
		}
		switch curr {
		case 0:
			switch c {
			case '!':
				isNegation = true
			case '&':
				isCount = true
			case ':':
				curr = 1
			default:
				curVar = append(curVar, c)
			}
		case 1:
			switch {
			case len(curKey) == 0 && (string(curVar) == "XML" || string(curVar) == "JSON"):
				// We are starting a XPATH
				curr = 3
				curKey = append(curKey, c)
			case c == '/':
				// We are starting a regex
				curr = 2
			case c == '\'':
				// we start a quoted regex
				// we go back to the loop to find /
				isquoted = true
			default:
				curKey = append(curKey, c)
			}
		case 2:
			// REGEX
			switch {
			case c == '/' && !isEscaped:
				// unescaped / will stop the regex
				curr = 1
			case c == '\\':
				curKey = append(curKey, '\\')
				isEscaped = !isEscaped
			default:
				curKey = append(curKey, c)
			}
		case 3:
			// XPATH
			curKey = append(curKey, c)
		}
	}
	return nil
}

// ParseOperator parses a seclang formatted operator string
// A operator must begin with @ (like @rx), if no operator is specified, rx
// will be used. Everything after the operator will be used as operator argument
func (p *RuleParser) ParseOperator(operator string) error {
	// default operator @RX
	operatorLen := len(operator)
	switch {
	case operatorLen == 0 || operator[0] != '@' && operator[0] != '!':
		operator = "@rx " + operator
	case operatorLen == 1 && operator == "!":
		operator = "!@rx"
	case operatorLen > 1 && operator[0] == '!' && operator[1] != '@':
		operator = "!@rx " + operator[1:]
	}

	// We clone strings to ensure a slice into larger rule definition isn't kept in
	// memory just to store operator information.
	opRaw, opdataRaw, _ := strings.Cut(operator, " ")
	op := strings.TrimSpace(opRaw)
	opdata := strings.TrimSpace(opdataRaw)

	if op[0] == '@' {
		// we trim @
		op = op[1:]
	} else if len(op) > 2 && op[0] == '!' && op[1] == '@' {
		// we trim !@
		op = op[2:]
	}

	opts := rules.OperatorOptions{
		Arguments: opdata,
		Path: []string{
			p.options.ParserConfig.ConfigDir,
		},
		Root: p.options.ParserConfig.Root,
	}

	if wd := p.options.ParserConfig.WorkingDir; wd != "" {
		opts.Path = append(opts.Path, wd)
	}

	opfn, err := operators.Get(op, opts)
	if err != nil {
		return err
	}
	p.rule.SetOperator(opfn, opRaw, opdata)
	return nil
}

// ParseDefaultActions parses a list of actions separated by a comma
// and assigns it to the specified phase.
// Default Actions MUST contain a phase
// Only one phase can be specified per WAF instance
// A disruptive action is required to be specified
// Each rule on the indicated phase will inherit the previously declared actions
// If the user overwrites the default actions, the default actions will be overwritten
func (p *RuleParser) ParseDefaultActions(actions string) error {
	act, err := parseActions(actions)
	if err != nil {
		return err
	}
	phase := types.RulePhase(0)
	defaultDisruptive := ""
	for _, action := range act {
		if action.Key == "phase" {
			phase, err = types.ParseRulePhase(action.Value)
			if err != nil {
				return err
			}
			continue
		}
		if action.Atype == rules.ActionTypeDisruptive {
			defaultDisruptive = action.Key
		}
		// SecDefaultActions can not contain metadata actions
		if action.Atype == rules.ActionTypeMetadata {
			return fmt.Errorf("SecDefaultAction must not contain metadata actions: %s", actions)
		}
		// Transformations are not suitable to be part of the default actions defined by SecDefaultActions
		if action.Key == "t" {
			return fmt.Errorf("SecDefaultAction must not contain transformation actions: %s", actions)
		}
	}
	if phase == 0 {
		return fmt.Errorf("SecDefaultAction must contain a phase")
	}
	if defaultDisruptive == "" {
		return fmt.Errorf("SecDefaultAction must contain a disruptive action: %s", actions)
	}
	if p.defaultActions[types.RulePhase(phase)] != nil {
		return fmt.Errorf("SecDefaultAction already defined for this phase: %s", actions)
	}
	p.defaultActions[types.RulePhase(phase)] = act
	return nil
}

// ParseActions parses a comma separated list of actions:arguments
// Arguments can be wrapper inside quotes
func (p *RuleParser) ParseActions(actions string) error {
	disabledActions := p.options.ParserConfig.DisabledRuleActions
	act, err := parseActions(actions)
	if err != nil {
		return err
	}
	// check if forbidden action:
	for _, a := range act {
		if utils.InSlice(a.Key, disabledActions) {
			return fmt.Errorf("%s rule action is disabled", a.Key)
		}
	}
	// first we execute metadata rules
	for _, a := range act {
		if a.Atype == rules.ActionTypeMetadata {
			if err := a.F.Init(p.rule, a.Value); err != nil {
				return fmt.Errorf("failed to init action %s: %s", a.Key, err.Error())
			}
		}
	}

	// if the rule is missing the phase, the default phase assigned is phase 2 (See NewRule())
	phase := p.rule.Phase_

	defaults := p.defaultActions[phase]
	if defaults != nil {
		act = mergeActions(act, defaults)
	}

	for _, action := range act {
		// now we evaluate non-metadata actions
		if action.Atype == rules.ActionTypeMetadata {
			continue
		}
		if err := action.F.Init(p.rule, action.Value); err != nil {
			return err
		}
		if err := p.rule.AddAction(action.Key, action.F); err != nil {
			return err
		}
	}
	return nil
}

// Rule returns the compiled rule
func (p *RuleParser) Rule() *corazawaf.Rule {
	return p.rule
}

// RuleOptions contains the options used to compile a rule
type RuleOptions struct {
	WithOperator bool
	WAF          *corazawaf.WAF
	ParserConfig ParserConfig
	Raw          string
	Directive    string
	Data         string
}

// ParseRule parses a rule from a string
// The string must match the seclang format
// In case WithOperator is false, the rule will be parsed without operator
// This function is created for external plugins directives
func ParseRule(options RuleOptions) (*corazawaf.Rule, error) {
	if strings.TrimSpace(options.Data) == "" {
		return nil, errors.New("empty rule")
	}

	var err error
	rp := RuleParser{
		options:        options,
		rule:           corazawaf.NewRule(),
		defaultActions: map[types.RulePhase][]ruleAction{},
	}
	var defaultActionsRaw []string
	// Default actions are persisted only inside the ParserConfig, therefore they are parsed every time a rule is parsed
	// and not just once when the SecDefaultAction is read.
	if options.ParserConfig.HasRuleDefaultActions {
		defaultActionsRaw = options.ParserConfig.RuleDefaultActions
	}
	disabledRuleOperators := options.ParserConfig.DisabledRuleOperators
	for _, da := range defaultActionsRaw {

		err = rp.ParseDefaultActions(da)
		if err != nil {
			return nil, err
		}
	}
	// If no default actions for phase 2 are defined, defaultActionsPhase2 variable (hardcoded default actions for phase 2) is used.
	if rp.defaultActions[types.PhaseRequestBody] == nil {
		err = rp.ParseDefaultActions(defaultActionsPhase2)
		if err != nil {
			return nil, err
		}
	}
	actions := ""

	if options.WithOperator {
		vars, operator, acts, err := parseActionOperator(options.Data)
		if err != nil {
			return nil, err
		}
		if utils.InSlice(operator, disabledRuleOperators) {
			return nil, fmt.Errorf("%s rule operator is disabled", operator)
		}
		if err := rp.ParseVariables(vars); err != nil {
			return nil, err
		}
		if err := rp.ParseOperator(operator); err != nil {
			return nil, err
		}
		if acts != "" {
			if err := rp.ParseActions(acts); err != nil {
				return nil, err
			}
		}
	} else {
		// quoted actions separated by comma (,)
		actions = utils.MaybeRemoveQuotes(options.Data)
		err = rp.ParseActions(actions)
		if err != nil {
			return nil, err
		}
	}
	rule := rp.Rule()
	rule.Raw_ = options.Raw
	rule.File_ = options.ParserConfig.ConfigFile
	rule.Line_ = options.ParserConfig.LastLine

	if parent := getLastRuleExpectingChain(options.WAF); parent != nil {
		rule.ParentID_ = parent.ID_
		lastChain := parent
		for lastChain.Chain != nil {
			lastChain = lastChain.Chain
		}
		// TODO we must remove defaultactions from chains
		rule.Phase_ = 0
		lastChain.Chain = rule
		return nil, nil
	}
	return rule, nil
}

func parseActionOperator(data string) (vars string, op string, actions string, err error) {
	// So only need to TrimLeft below
	data = strings.Trim(data, " ")
	vars, rest, ok := strings.Cut(data, " ")
	if !ok {
		return "", "", "", fmt.Errorf("invalid format for rule with operator: %q", data)
	}

	rest = strings.TrimLeft(rest, " ")

	if len(rest) == 0 || rest[0] != '"' {
		return "", "", "", fmt.Errorf("invalid operator for rule with operator: %q", data)
	}

	op, rest, err = cutQuotedString(rest)
	if err != nil {
		return
	}
	op = utils.MaybeRemoveQuotes(op)

	rest = strings.TrimLeft(rest, " ")
	if len(rest) == 0 {
		// No actions
		return
	}

	if len(rest) < 2 || rest[0] != '"' || rest[len(rest)-1] != '"' {
		return "", "", "", fmt.Errorf("invalid actions for rule with operator: %q", data)
	}
	actions = utils.MaybeRemoveQuotes(rest)

	return
}

func cutQuotedString(s string) (string, string, error) {
	if len(s) == 0 || s[0] != '"' {
		return "", "", fmt.Errorf("expected quoted string: %q", s)
	}

	for i := 1; i < len(s); i++ {
		// Search until first quote that isn't part of an escape sequence.
		if s[i] != '"' {
			continue
		}
		if s[i-1] == '\\' {
			continue
		}

		return s[:i+1], s[i+1:], nil
	}

	return "", "", fmt.Errorf("expected terminating quote: %q", s)
}

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
	// chain rules with ID -1 are not processed
	if parent.HasChain && parent.Chain == nil {
		return lastRule
	}

	return nil
}

const unset = -1

// parseActions will assign the function name, arguments and
// function (pkg.actions) for each action split by comma (,)
// Action arguments are allowed to wrap values between colons(”)
func parseActions(actions string) ([]ruleAction, error) {
	var res []ruleAction
	var err error
	disruptiveActionIndex := unset

	beforeKey := -1 // index before first char of key
	afterKey := -1  // index after last char of key and before first char of value

	inQuotes := false

	for i := 1; i < len(actions); i++ {
		c := actions[i]
		if actions[i-1] == '\\' {
			// Escaped character, no need to process
			continue
		}
		if c == '\'' {
			inQuotes = !inQuotes
			continue
		}
		if inQuotes {
			// Inside quotes, no need to process
			continue
		}
		switch c {
		case ':':
			if afterKey != -1 {
				// Reading value, no need to process
				continue
			}
			afterKey = i
		case ',':
			var val string
			if afterKey == -1 {
				// No value, we only have a key
				afterKey = i
			} else {
				val = actions[afterKey+1 : i]
			}
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
		// No value, we only have a key
		afterKey = len(actions)
	} else {
		val = actions[afterKey+1:]
	}
	res, _, err = appendRuleAction(res, actions[beforeKey+1:afterKey], val, disruptiveActionIndex)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func appendRuleAction(res []ruleAction, key string, val string, disruptiveActionIndex int) ([]ruleAction, int, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	val = strings.TrimSpace(val) // We may want to keep case sensitive values (e.g. Messages)
	val = utils.MaybeRemoveQuotes(val)
	f, err := actionsmod.Get(key)
	if err != nil {
		return res, unset, err
	}
	if f.Type() == rules.ActionTypeDisruptive && disruptiveActionIndex != unset {
		// There can only be one disruptive action per rule (if there are multiple disruptive
		// actions present, or inherited, only the last one will take effect).
		// Therefore, if we encounter another disruptive action, we replace the previous one.
		res[disruptiveActionIndex] = ruleAction{
			Key:   key,
			Value: val,
			F:     f,
			Atype: f.Type(),
		}
	} else {
		if f.Type() == rules.ActionTypeDisruptive {
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

/*
So here is my research:
SecDefaultAction must contain a phase and a disruptive action
They will only be merged if the match the same phase
If the rule disruptive action is block it will inherit the defaultaction disruptive actions
DefaultAction's disruptive action will be added to the rule only if there is no DA or DA is block
If we have:
SecDefaultAction "phase:2,deny,status:403,log"
Then we have a Rule:
SecAction "id:1, phase:2, block, nolog"
The rule ID 1 will inherit default actions and become
SecAction "id:1, phase:2, status:403, log, nolog, deny"
In the future I shall optimize that redundant log and nolog, it won't actually change anything but would look cooler
*/
func mergeActions(origin []ruleAction, defaults []ruleAction) []ruleAction {
	var res []ruleAction
	var da ruleAction // Disruptive action
	for _, action := range defaults {
		if action.Atype == rules.ActionTypeDisruptive {
			da = action
			continue
		}
		if action.Atype == rules.ActionTypeMetadata {
			continue
		}
		res = append(res, action)
	}
	hasDa := false
	for _, action := range origin {
		if action.Atype == rules.ActionTypeDisruptive {
			if action.Key != "block" {
				hasDa = true
				// We add the default rule DA in case this is no block
				res = append(res, action)
			}
		} else {
			res = append(res, action)
		}
	}
	if !hasDa {
		// We add the default disruptive action if there is no DA in rule or DA is block
		res = append(res, da)
	}

	return res
}
