// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// ruleActionParams is used as a wrapper to store the action name
// and parameters, basically for logging purposes.
type ruleActionParams struct {
	// The name of the action, used for logging
	Name string

	// The action to be executed
	Function rules.Action
}

// Operator is a container for an operator,
type ruleOperatorParams struct {
	// Operator to be used
	Operator rules.Operator

	// Function name (ex @rx)
	Function string
	// Data to initialize the operator
	Data string
	// If true, rule will match if op.Evaluate returns false
	Negation bool
}

type ruleVariableException struct {
	// The string key for the variable that is going to be requested
	// If KeyRx is not nil, KeyStr is ignored
	KeyStr string

	// The key for the variable that is going to be requested
	// If nil, KeyStr is going to be used
	KeyRx *regexp.Regexp
}

// RuleVariable is compiled during runtime by transactions
// to get values from the transaction's variables
// It supports xml, regex, exceptions and many more features
type ruleVariableParams struct {
	// If true, the count of results will be returned
	Count bool

	// The VARIABLE that will be requested
	Variable variables.RuleVariable

	// The key for the variable that is going to be requested
	// If nil, KeyStr is going to be used
	KeyRx *regexp.Regexp

	// The string key for the variable that is going to be requested
	// If KeyRx is not nil, KeyStr is ignored
	KeyStr string

	// A slice of key exceptions
	Exceptions []ruleVariableException
}

type ruleTransformationParams struct {
	// The transformation function to be used
	Function rules.Transformation
}

// Rule is used to test a Transaction against certain operators
// and execute actions
type Rule struct {
	corazarules.RuleMetadata
	// Contains a list of variables that will be compiled
	// by a transaction
	variables []ruleVariableParams

	// Contains a pointer to the operator struct used
	// SecActions and SecMark can have nil Operators
	operator *ruleOperatorParams

	// List of transformations to be evaluated
	// In the future, transformations might be run by the
	// action itself, not sure yet
	transformations []ruleTransformationParams

	transformationsID int

	// Slice of initialized actions to be evaluated during
	// the rule evaluation process
	actions []ruleActionParams

	// Contains the Id of the parent rule if you are inside
	// a chain. Otherwise, it will be 0
	ParentID_ int

	// Capture is used by the transaction to tell the operator
	// to capture variables on TX:0-9
	Capture bool

	// Contains the child rule to chain, nil if there are no chains
	Chain *Rule

	// DisruptiveStatus is the status that will be set to interruptions
	// by disruptive rules
	DisruptiveStatus int

	// Message text to be macro expanded and logged
	// In future versions we might use a special type of string that
	// supports cached macro expansions. For performance
	Msg macro.Macro

	// Rule logdata
	LogData macro.Macro

	// If true, triggering this rule write to the error log
	Log bool

	// If true, triggering this rule write to the audit log
	Audit bool

	// If true, the transformations will be multi matched
	MultiMatch bool

	HasChain bool

	// inferredPhases is the inferred phases the rule is relevant for
	// based on the processed variables.
	inferredPhases [types.PhaseLogging + 1]bool
}

func (r *Rule) ParentID() int {
	return r.ParentID_
}

func (r *Rule) Status() int {
	return r.DisruptiveStatus
}

// Evaluate will evaluate the current rule for the indicated transaction
// If the operator matches, actions will be evaluated, and it will return
// the matched variables, keys and values (MatchData)
func (r *Rule) Evaluate(phase types.RulePhase, tx rules.TransactionState, cache map[transformationKey]*transformationValue) {
	r.doEvaluate(phase, tx.(*Transaction), cache)
}

func (r *Rule) doEvaluate(phase types.RulePhase, tx *Transaction, cache map[transformationKey]*transformationValue) []types.MatchData {
	if r.Capture {
		tx.Capture = true
	}
	rid := r.ID_
	if rid == 0 {
		rid = r.ParentID_
	}

	var matchedValues []types.MatchData
	// we log if we are the parent rule
	tx.DebugLogger().Debug().Int("rule_id", rid).Msg("Evaluating rule")
	defer tx.DebugLogger().Debug().Int("rule_id", rid).Msg("Finish evaluating rule")
	ruleCol := tx.variables.rule
	ruleCol.SetIndex("id", 0, strconv.Itoa(rid))
	if r.Msg != nil {
		ruleCol.SetIndex("msg", 0, r.Msg.String())
	}
	ruleCol.SetIndex("rev", 0, r.Rev_)
	if r.LogData != nil {
		ruleCol.SetIndex("logdata", 0, r.LogData.String())
	}
	ruleCol.SetIndex("severity", 0, r.Severity_.String())
	// SecMark and SecAction uses nil operator
	if r.operator == nil {
		tx.DebugLogger().Debug().Int("rule_id", rid).Msg("Forcing rule to match")
		md := &corazarules.MatchData{}
		if r.Msg != nil {
			md.Message_ = r.Msg.Expand(tx)
		}
		if r.LogData != nil {
			md.Data_ = r.LogData.Expand(tx)
		}
		matchedValues = append(matchedValues, md)
		r.matchVariable(tx, md)
	} else {
		ecol := tx.ruleRemoveTargetByID[r.ID_]
		for _, v := range r.variables {
			// TODO(anuraaga): Support skipping variables based on phase for rule chains too.
			if multiphaseEvaluation && !r.HasChain && r.ParentID_ == 0 {
				min := minPhase(v.Variable)
				// When multiphase evaluation is enabled, any variable is evaluated at its
				// earliest possible phase, so we skip it if the rule refers to other phases
				// to avoid double-evaluation.
				if min != types.PhaseUnknown && min != phase {
					continue
				}
			}
			var values []types.MatchData
			for _, c := range ecol {
				if c.Variable == v.Variable {
					// TODO shall we check the pointer?
					v.Exceptions = append(v.Exceptions, ruleVariableException{c.KeyStr, nil})
				}
			}

			values = tx.GetField(v)
			tx.DebugLogger().Debug().
				Int("rule_id", rid).
				Str("variable", v.Variable.Name()).
				Msg("Expanding arguments for rule")
			for i, arg := range values {
				tx.DebugLogger().Debug().Int("rule_id", rid).Msg("Transforming argument for rule")
				args, errs := r.transformArg(arg, i, cache)
				if len(errs) > 0 {
					log := tx.DebugLogger().Debug().Int("rule_id", rid)
					if log.IsEnabled() {
						for i, err := range errs {
							log = log.Str(fmt.Sprintf("errors[%d]", i), err.Error())
						}
						log.Msg("Error transforming argument for rule")
					}
				}
				tx.DebugLogger().Debug().Int("rule_id", rid).Msg("Arguments transformed for rule")

				// args represents the transformed variables
				for _, carg := range args {
					match := r.executeOperator(carg, tx)
					if match {
						mr := &corazarules.MatchData{
							Variable_: arg.Variable(),
							Key_:      arg.Key(),
							Value_:    carg,
						}
						// Set the txn variables for expansions before usage
						r.matchVariable(tx, mr)

						if r.Msg != nil {
							mr.Message_ = r.Msg.Expand(tx)
						}
						if r.LogData != nil {
							mr.Data_ = r.LogData.Expand(tx)
						}
						matchedValues = append(matchedValues, mr)
						tx.DebugLogger().Debug().
							Int("rule_id", rid).
							Str("operator_function", r.operator.Function).
							Str("operator_data", r.operator.Data).
							Str("arg", carg).
							Msg("Evaluating operator: MATCH")
					} else {
						tx.DebugLogger().Debug().
							Int("rule_id", rid).
							Str("operator_function", r.operator.Function).
							Str("operator_data", r.operator.Data).
							Str("arg", carg).
							Msg("Evaluating operator: NO MATCH")
					}
				}
			}
		}
	}

	if len(matchedValues) == 0 {
		return matchedValues
	}

	// disruptive actions and rules affecting the rule flow are only evaluated by parent rules
	if r.ParentID_ == 0 {
		// we only run the chains for the parent rule
		for nr := r.Chain; nr != nil; {
			tx.DebugLogger().Debug().Int("rule_id", rid).Msg("Evaluating rule chain")
			matchedChainValues := nr.doEvaluate(phase, tx, cache)
			if len(matchedChainValues) == 0 {
				return matchedChainValues
			}
			matchedValues = append(matchedValues, matchedChainValues...)
			nr = nr.Chain
		}

		for _, a := range r.actions {
			if a.Function.Type() == rules.ActionTypeFlow {
				// Flow actions are evaluated also if the rule engine is set to DetectionOnly
				tx.DebugLogger().Debug().Int("rule_id", rid).Str("action", a.Name).Msg("Evaluating flow action for rule")
				a.Function.Evaluate(r, tx)
			} else if a.Function.Type() == rules.ActionTypeDisruptive && tx.RuleEngine == types.RuleEngineOn {
				// The parser enforces that the disruptive action is just one per rule (if more than one, only the last one is kept)
				tx.DebugLogger().Debug().Int("rule_id", rid).Str("action", a.Name).Msg("Executing disruptive action for rule")
				a.Function.Evaluate(r, tx)
			}
		}
		if r.ID_ != 0 {
			// we avoid matching chains and secmarkers
			tx.MatchRule(r, matchedValues)
		}
	}
	return matchedValues
}

func (r *Rule) transformArg(arg types.MatchData, argIdx int, cache map[transformationKey]*transformationValue) ([]string, []error) {
	if r.MultiMatch {
		// TODO in the future, we don't need to run every transformation
		// We could try for each until found
		return r.executeTransformationsMultimatch(arg.Value())
	} else {
		switch {
		case len(r.transformations) == 0:
			return []string{arg.Value()}, nil
		case arg.Variable().Name() == "TX":
			// no cache for TX
			arg, errs := r.executeTransformations(arg.Value())
			return []string{arg}, errs
		default:
			// NOTE: See comment on transformationKey struct to understand this hacky code
			argKey := arg.Key()
			argKeyPtr := (*reflect.StringHeader)(unsafe.Pointer(&argKey)).Data
			key := transformationKey{
				argKey:            argKeyPtr,
				argIndex:          argIdx,
				argVariable:       arg.Variable(),
				transformationsID: r.transformationsID,
			}
			if cached, ok := cache[key]; ok {
				return cached.args, cached.errs
			} else {
				ars, es := r.executeTransformations(arg.Value())
				args := []string{ars}
				errs := es
				cache[key] = &transformationValue{
					args: args,
					errs: es,
				}
				return args, errs
			}
		}
	}
}

func (r *Rule) matchVariable(tx *Transaction, m *corazarules.MatchData) {
	rid := r.ID_
	if rid == 0 {
		rid = r.ParentID_
	}
	if m.Variable() != variables.Unknown {
		tx.DebugLogger().Debug().
			Int("rule_id", rid).
			Str("variable_name", m.Variable().Name()).
			Str("key", m.Key()).
			Msg("Matching rule")
	}
	// we must match the vars before running the chains

	// We run non-disruptive actions even if there is no chain match
	tx.matchVariable(m)
	for _, a := range r.actions {
		if a.Function.Type() == rules.ActionTypeNondisruptive {
			tx.DebugLogger().Debug().Str("action", a.Name).Msg("Evaluating action")
			a.Function.Evaluate(r, tx)
		}
	}
}

// AddAction adds an action to the rule
func (r *Rule) AddAction(name string, action rules.Action) error {
	// TODO add more logic, like one persistent action per rule etc
	r.actions = append(r.actions, ruleActionParams{
		Name:     name,
		Function: action,
	})
	return nil
}

// AddVariable adds a variable to the rule
// The key can be a regexp.Regexp, a string or nil, in case of regexp
// it will be used to match the variable, in case of string it will
// be a fixed match, in case of nil it will match everything
func (r *Rule) AddVariable(v variables.RuleVariable, key string, iscount bool) error {
	var re *regexp.Regexp
	if len(key) > 2 && key[0] == '/' && key[len(key)-1] == '/' {
		key = key[1 : len(key)-1]
		re = regexp.MustCompile(key)
	}

	r.variables = append(r.variables, ruleVariableParams{
		Count:      iscount,
		Variable:   v,
		KeyStr:     strings.ToLower(key),
		KeyRx:      re,
		Exceptions: []ruleVariableException{},
	})
	return nil
}

// AddVariableNegation adds an exception to a variable
// It passes through if the variable is not used
// It returns an error if the selector is empty,
// or applied on an undefined rule
// for example:
// OK: SecRule ARGS|!ARGS:id "..."
// OK: SecRule !ARGS:id "..."
// ERROR: SecRule !ARGS: "..."
func (r *Rule) AddVariableNegation(v variables.RuleVariable, key string) error {
	var re *regexp.Regexp
	if len(key) > 2 && key[0] == '/' && key[len(key)-1] == '/' {
		key = key[1 : len(key)-1]
		re = regexp.MustCompile(key)
	}
	// Prevent sigsev
	if r == nil {
		return fmt.Errorf("cannot create a variable exception for an undefined rule")
	}
	for i, rv := range r.variables {
		if rv.Variable == v {
			rv.Exceptions = append(rv.Exceptions, ruleVariableException{strings.ToLower(key), re})
			r.variables[i] = rv
		}
	}
	return nil
}

var transformationIDToName = []string{""}
var transformationNameToID = map[string]int{"": 0}
var transformationIDsLock = sync.Mutex{}

func transformationID(currentID int, transformationName string) int {
	transformationIDsLock.Lock()
	defer transformationIDsLock.Unlock()

	currName := transformationIDToName[currentID]
	nextName := fmt.Sprintf("%s+%s", currName, transformationName)
	if id, ok := transformationNameToID[nextName]; ok {
		return id
	}

	id := len(transformationIDToName)
	transformationIDToName = append(transformationIDToName, nextName)
	transformationNameToID[nextName] = id
	return id
}

// AddTransformation adds a transformation to the rule
// it fails if the transformation cannot be found
func (r *Rule) AddTransformation(name string, t rules.Transformation) error {
	if t == nil || name == "" {
		return fmt.Errorf("invalid transformation %q not found", name)
	}
	r.transformations = append(r.transformations, ruleTransformationParams{Function: t})
	r.transformationsID = transformationID(r.transformationsID, name)
	return nil
}

// ClearTransformations clears all the transformations
// it is mostly used by the "none" transformation
func (r *Rule) ClearTransformations() {
	r.transformations = []ruleTransformationParams{}
}

// SetOperator sets the operator of the rule
// There can be only one operator per rule
// functionName and params are used for logging
func (r *Rule) SetOperator(operator rules.Operator, functionName string, params string) {
	r.operator = &ruleOperatorParams{
		Operator: operator,
		Function: functionName,
		Data:     params,
		Negation: len(functionName) > 0 && functionName[0] == '!',
	}
}

func (r *Rule) executeOperator(data string, tx *Transaction) (result bool) {
	result = r.operator.Operator.Evaluate(tx, data)
	if r.operator.Negation {
		result = !result
	}
	return
}

func (r *Rule) executeTransformationsMultimatch(value string) ([]string, []error) {
	res := []string{value}
	var errs []error
	var err error
	for _, t := range r.transformations {
		value, err = t.Function(value)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		res = append(res, value)
	}
	return res, errs
}

func (r *Rule) executeTransformations(value string) (string, []error) {
	var errs []error
	for _, t := range r.transformations {
		v, err := t.Function(value)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		value = v
	}
	return value, errs
}

// NewRule returns a new initialized rule
// By default, the rule is set to phase 2
func NewRule() *Rule {
	return &Rule{
		RuleMetadata: corazarules.RuleMetadata{
			Phase_: 2,
			Tags_:  []string{},
		},
	}
}

// minPhase returns the earliest phase a variable may be populated.
// NOTE: variables.Args and variables.ArgsNames should ideally be evaluated
// both in phase 1 and 2, but rules can set state in the transaction, e.g. a
// counter, which prevents evaluating any variable multiple times.
func minPhase(v variables.RuleVariable) types.RulePhase {
	switch v {
	case variables.ResponseContentType:
		return types.PhaseResponseHeaders
	case variables.UniqueID:
		return types.PhaseRequestHeaders
	case variables.ArgsCombinedSize:
		// Size changes between phase 1 and 2 so evaluate both times
		return types.PhaseRequestHeaders
	case variables.FilesCombinedSize:
		return types.PhaseRequestBody
	case variables.FullRequestLength:
		// Not populated by Coraza
		return types.PhaseRequestBody
	case variables.InboundDataError:
		// Not populated by Coraza
		return types.PhaseRequestBody
	case variables.MatchedVar:
		// MatchedVar is only for logging, not evaluation
		return types.PhaseUnknown
	case variables.MatchedVarName:
		// MatchedVar is only for logging, not evaluation
		return types.PhaseUnknown
	// MultipartBoundaryWhitespace kept for compatibility
	case variables.MultipartDataAfter:
		// Not populated by Coraza
		return types.PhaseRequestBody
	case variables.OutboundDataError:
		return types.PhaseResponseBody
	case variables.QueryString:
		return types.PhaseRequestHeaders
	case variables.RemoteAddr:
		return types.PhaseRequestHeaders
	case variables.RemoteHost:
		// Not implemented
		return types.PhaseRequestHeaders
	case variables.RemotePort:
		return types.PhaseRequestHeaders
	case variables.ReqbodyError:
		return types.PhaseRequestBody
	case variables.ReqbodyErrorMsg:
		return types.PhaseRequestBody
	case variables.ReqbodyProcessorError:
		return types.PhaseRequestBody
	case variables.ReqbodyProcessorErrorMsg:
		return types.PhaseRequestBody
	case variables.ReqbodyProcessor:
		// Configuration of Coraza itself, though shouldn't be used in phases
		return types.PhaseUnknown
	case variables.RequestBasename:
		return types.PhaseRequestHeaders
	case variables.RequestBody:
		return types.PhaseRequestBody
	case variables.RequestBodyLength:
		return types.PhaseRequestBody
	case variables.RequestFilename:
		return types.PhaseRequestHeaders
	case variables.RequestLine:
		return types.PhaseRequestHeaders
	case variables.RequestMethod:
		return types.PhaseRequestHeaders
	case variables.RequestProtocol:
		return types.PhaseRequestHeaders
	case variables.RequestURI:
		return types.PhaseRequestHeaders
	case variables.RequestURIRaw:
		return types.PhaseRequestHeaders
	case variables.ResponseBody:
		return types.PhaseResponseBody
	case variables.ResponseContentLength:
		return types.PhaseResponseBody
	case variables.ResponseProtocol:
		return types.PhaseResponseHeaders
	case variables.ResponseStatus:
		return types.PhaseResponseHeaders
	case variables.ServerAddr:
		// Configuration of the server itself
		return types.PhaseRequestHeaders
	case variables.ServerName:
		// Configuration of the server itself
		return types.PhaseRequestHeaders
	case variables.ServerPort:
		// Configuration of the server itself
		return types.PhaseRequestHeaders
	case variables.HighestSeverity:
		// Result of matching, not used in phaes
		return types.PhaseUnknown
	case variables.StatusLine:
		return types.PhaseResponseHeaders
	case variables.Duration:
		// If used in matching, would need to be defined for multiple inferredPhases to make sense
		return types.PhaseUnknown
	case variables.ResponseHeadersNames:
		return types.PhaseResponseHeaders
	case variables.RequestHeadersNames:
		return types.PhaseRequestHeaders
	case variables.Args:
		// Updated between headers and body
		return types.PhaseRequestBody
	case variables.ArgsGet:
		return types.PhaseRequestHeaders
	case variables.ArgsPost:
		return types.PhaseRequestBody
	case variables.ArgsPath:
		return types.PhaseRequestHeaders
	case variables.FilesSizes:
		return types.PhaseRequestBody
	case variables.FilesNames:
		return types.PhaseRequestBody
	case variables.FilesTmpContent:
		// Not populated by Coraza
		return types.PhaseRequestBody
	case variables.MultipartFilename:
		return types.PhaseRequestBody
	case variables.MultipartName:
		return types.PhaseRequestBody
	case variables.MatchedVarsNames:
		// Result of execution, not used in inferredPhases
		return types.PhaseUnknown
	case variables.MatchedVars:
		// Result of execution, not used in inferredPhases
		return types.PhaseUnknown
	case variables.Files:
		return types.PhaseRequestBody
	case variables.RequestCookies:
		return types.PhaseRequestHeaders
	case variables.RequestHeaders:
		return types.PhaseRequestHeaders
	case variables.ResponseHeaders:
		return types.PhaseResponseHeaders
	case variables.Geo:
		// Not populated by Coraza
		return types.PhaseRequestHeaders
	case variables.RequestCookiesNames:
		return types.PhaseRequestHeaders
	case variables.FilesTmpNames:
		return types.PhaseRequestBody
	case variables.ArgsNames:
		// Updated between headers and body
		return types.PhaseRequestBody
	case variables.ArgsGetNames:
		return types.PhaseRequestHeaders
	case variables.ArgsPostNames:
		return types.PhaseRequestBody
	case variables.TX:
		return types.PhaseUnknown
	case variables.Rule:
		// Shouldn't be used in phases
		return types.PhaseUnknown
	case variables.JSON:
		return types.PhaseRequestBody
	case variables.Env:
		return types.PhaseRequestHeaders
	case variables.UrlencodedError:
		return types.PhaseRequestHeaders
	case variables.ResponseArgs:
		return types.PhaseResponseBody
	case variables.ResponseXML:
		return types.PhaseResponseBody
	case variables.RequestXML:
		return types.PhaseRequestBody
	case variables.XML:
		return types.PhaseRequestBody
	case variables.MultipartPartHeaders:
		return types.PhaseRequestBody
	}

	return types.PhaseUnknown
}
