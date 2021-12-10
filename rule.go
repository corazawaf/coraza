// Copyright 2021 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http:// www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package coraza

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jptosso/coraza-waf/v2/types"
	"github.com/jptosso/coraza-waf/v2/types/variables"
	"go.uber.org/zap"
)

// RuleTransformation is used to create transformation plugins
// See the documentation for more information
// If a transformation fails to run it will return the same string
// and an error, errors are only used for logging, it won't stop
// the execution of the rule
type RuleTransformation = func(input string) (string, error)

// RuleAction is used used to create Action plugins
// See the documentation: https://www.coraza.io/docs/waf/actions
type RuleAction interface {
	// Initializes an action, will be done during compilation
	Init(*Rule, string) error
	// Evaluate will be done during rule evaluation
	Evaluate(*Rule, *Transaction)
	// Type will return the rule type, it's used by Evaluate
	// to choose when to evaluate each action
	Type() types.RuleActionType
}

// ruleActionParams is used as a wrapper to store the action name
// and parameters, basically for logging purposes.
type ruleActionParams struct {
	// The name of the action, used for logging
	Name string

	// Parameters used by the action
	Param string

	// The action to be executed
	Function RuleAction
}

// RuleOperator interface is used to define rule @operators
type RuleOperator interface {
	// Init is used during compilation to setup and cache
	// the operator
	Init(string) error
	// Evaluate is used during the rule evaluation,
	// it returns true if the operator succeeded against
	// the input data for the transaction
	Evaluate(*Transaction, string) bool
}

// RuleOperator is a container for an operator,
type ruleOperatorParams struct {
	// Operator to be used
	Operator RuleOperator

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
	// We store the name for performance
	Name string

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
	// The transformation to be used, used for logging
	Name string

	// The transformation function to be used
	Function RuleTransformation
}

// Rule is used to test a Transaction against certain operators
// and execute actions
type Rule struct {
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

	// Slice of initialized actions to be evaluated during
	// the rule evaluation process
	actions []ruleActionParams

	// Contains the Id of the parent rule if you are inside
	// a chain. Otherwise it will be 0
	ParentID int

	// Capture is used by the transaction to tell the operator
	// to capture variables on TX:0-9
	Capture bool

	// Used to mark a rule as a secmarker and alter flows
	SecMark string

	// Contains the raw rule code
	Raw string

	// Contains the child rule to chain, nil if there are no chains
	Chain *Rule

	// Where is this rule stored
	File string

	// Line of the file where this rule was found
	Line int

	// METADATA
	// Rule unique identifier, can be a an int
	ID int

	// Rule tag list
	Tags []string

	// Rule execution phase 1-5
	Phase types.RulePhase

	// Message text to be macro expanded and logged
	// In future versions we might use a special type of string that
	// supports cached macro expansions. For performance
	Msg Macro

	// Rule revision value
	Rev string

	// Rule maturity index
	Maturity int

	// RuleSet Version
	Version string

	// Rule accuracy
	Accuracy int

	// Rule severity
	Severity types.RuleSeverity

	// Rule logdata
	LogData Macro

	// If true, triggering this rule write to the error log
	Log bool

	// If true, triggering this rule write to the audit log
	Audit bool

	// If true, the transformations will be multimatched
	MultiMatch bool

	// Used for error logging
	Disruptive bool
}

// Evaluate will evaluate the current rule for the indicated transaction
// If the operator matches, actions will be evaluated and it will return
// the matched variables, keys and values (MatchData)
func (r *Rule) Evaluate(tx *Transaction) []MatchData {
	if r.Capture {
		tx.Capture = true
		defer tx.resetCaptures()
	}
	rid := r.ID
	if rid == 0 {
		rid = r.ParentID
	}
	tx.Waf.Logger.Debug("Evaluating rule",
		zap.Int("rule", rid),
		zap.String("raw", r.Raw),
		zap.String("tx", tx.ID),
		zap.String("event", "EVALUATE_RULE"),
	)
	matchedValues := []MatchData{}
	tx.GetCollection(variables.Rule).SetData(map[string][]string{
		"id":       {strconv.Itoa(rid)},
		"msg":      {r.Msg.Expand(tx)},
		"rev":      {r.Rev},
		"logdata":  {r.LogData.Expand(tx)},
		"severity": {r.Severity.String()},
	})
	// secmarkers and secactions will always match

	// SecMark and SecAction uses nil operator
	if r.operator == nil {
		tx.Waf.Logger.Debug("Forcing rule match", zap.String("txid", tx.ID),
			zap.Int("rule", r.ID),
			zap.String("event", "RULE_FORCE_MATCH"),
		)
		matchedValues = []MatchData{
			{
				Key:   "",
				Value: "",
			},
		}
	} else {
		ecol := tx.ruleRemoveTargetByID[r.ID]
		for _, v := range r.variables {
			var values []MatchData
			for _, c := range ecol {
				if c.Variable == v.Variable {
					// TODO shall we check the pointer?
					v.Exceptions = append(v.Exceptions, ruleVariableException{c.KeyStr, nil})
				}
			}

			values = tx.GetField(v)
			if len(values) == 0 {
				// TODO should we run the operators here?
				continue
			}
			tx.Waf.Logger.Debug("Expanding arguments",
				zap.Int("rule", rid),
				zap.String("tx", tx.ID),
				zap.Int("count", len(values)),
			)
			for _, arg := range values {
				var args []string
				tx.Waf.Logger.Debug("Transforming argument",
					zap.Int("rule", rid),
					zap.String("tx", tx.ID),
					zap.String("argument", arg.Value),
				)
				var errs []error
				if r.MultiMatch {
					// TODO in the future, we don't need to run every transformation
					// We could try for each until found
					args, errs = r.executeTransformationsMultimatch(arg.Value)
				} else {
					ars, es := r.executeTransformations(arg.Value)
					args = []string{ars}
					errs = es
				}
				if len(errs) > 0 {
					tx.Waf.Logger.Error("Error transforming argument",
						zap.Int("rule", rid),
						zap.String("tx", tx.ID),
						zap.String("argument", arg.Value),
						zap.Errors("errors", errs),
					)
				}
				tx.Waf.Logger.Debug("Arguments transformed",
					zap.Int("rule", rid),
					zap.String("tx", tx.ID),
					zap.Strings("arguments", args),
				)

				// args represents the transformed variables
				for _, carg := range args {
					match := r.executeOperator(carg, tx)
					if match {
						matchedValues = append(matchedValues, MatchData{
							VariableName: v.Variable.Name(),
							Variable:     arg.Variable,
							Key:          arg.Key,
							Value:        carg,
						})
					}
					tx.Waf.Logger.Debug("Evaluate rule operator", zap.String("txid", tx.ID),
						zap.Int("rule", rid),
						zap.String("event", "EVALUATE_RULE_OPERATOR"),
						zap.String("operator", r.operator.Function), // TODO fix
						zap.String("data", carg),
						zap.String("variable", arg.Variable.Name()),
						zap.String("key", arg.Key),
						zap.String("value", carg),
						zap.Bool("result", match),
					)
				}
			}
		}
	}

	if len(matchedValues) == 0 {
		// No match for variables
		return matchedValues
	}

	tx.Waf.Logger.Debug("Attempting to match values", zap.String("txid", tx.ID),
		zap.Int("rule", rid),
		zap.String("event", "EVALUATE_RULE_OPERATOR"),
		zap.Any("values", matchedValues))
	// we must match the vars before running the chains
	tx.MatchVariable(matchedValues[0])

	// We run non disruptive actions even if there is no chain match
	for _, a := range r.actions {
		if a.Function.Type() == types.ActionTypeNondisruptive {
			tx.Waf.Logger.Debug("evaluating action", zap.String("type", "non_disruptive"),
				zap.String("txid", tx.ID), zap.Int("rule", rid), zap.String("action", a.Name))
			a.Function.Evaluate(r, tx)
		}
	}

	if r.Chain != nil {
		nr := r.Chain
		tx.Waf.Logger.Debug("Evaluating rule chain", zap.Int("rule", rid), zap.String("raw", nr.Raw))
		for nr != nil {
			m := nr.Evaluate(tx)
			if len(m) == 0 {
				// we fail the chain
				return []MatchData{}
			}

			matchedValues = append(matchedValues, m...)
			nr = nr.Chain
		}
	}
	if r.ParentID == 0 {
		// action log is required to add the rule to matched rules
		if r.Log {
			tx.MatchRule(MatchedRule{
				Rule:            *r,
				MatchedData:     matchedValues[0],
				Message:         r.Msg.Expand(tx),
				Data:            r.LogData.Expand(tx),
				URI:             tx.GetCollection(variables.RequestURI).GetFirstString(""),
				ID:              tx.ID,
				Disruptive:      r.Disruptive,
				ServerIPAddress: tx.GetCollection(variables.ServerAddr).GetFirstString(""),
				ClientIPAddress: tx.GetCollection(variables.RemoteAddr).GetFirstString(""),
			})
		}
		// we need to add disruptive actions in the end, otherwise they would be triggered without their chains.
		tx.Waf.Logger.Debug("detecting rule disruptive action", zap.String("txid", tx.ID), zap.Int("rule", r.ID))
		for _, a := range r.actions {
			if a.Function.Type() == types.ActionTypeDisruptive || a.Function.Type() == types.ActionTypeFlow {
				tx.Waf.Logger.Debug("evaluating action", zap.String("type", "disruptive"),
					zap.String("txid", tx.ID), zap.Int("rule", rid), zap.String("action", a.Name))
				a.Function.Evaluate(r, tx)
			}
		}
	}
	tx.Waf.Logger.Debug("finished evaluating rule", zap.String("txid", tx.ID),
		zap.Int("rule", rid),
		zap.Int("matched_values", len(matchedValues)),
		zap.String("event", "FINISH_RULE"),
	)
	return matchedValues
}

// AddAction adds an action to the rule
func (r *Rule) AddAction(name string, action RuleAction) error {
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
func (r *Rule) AddVariable(v variables.RuleVariable, key interface{}, iscount bool) error {
	var re *regexp.Regexp
	str := ""
	switch v := key.(type) {
	case *regexp.Regexp:
		re = v
		str = re.String()
	case string:
		str = strings.ToLower(v)
	case nil:
		// we allow this
	default:
		return fmt.Errorf("invalid key type %T", v)
	}
	r.variables = append(r.variables, ruleVariableParams{
		Count:      iscount,
		Variable:   v,
		KeyStr:     str,
		KeyRx:      re,
		Exceptions: []ruleVariableException{},
	})
	return nil
}

// AddVariableNegation adds an exception to a variable
// It returns an error if the variable is not used or
// the selector is empty, for example:
// OK: SecRule ARGS|!ARGS:id "..."
// ERROR: SecRule !ARGS:id "..."
// ERROR: SecRule !ARGS: "..."
func (r *Rule) AddVariableNegation(v variables.RuleVariable, key interface{}) error {
	counter := 0
	var re *regexp.Regexp
	str := ""
	switch v := key.(type) {
	case string:
		st := v
		if st == "" {
			return fmt.Errorf("invalid variable negation key, it cannot be empty")
		}
		str = strings.ToLower(st)
	case *regexp.Regexp:
		if v.String() == "" {
			return fmt.Errorf("invalid variable negation key, it cannot be an empty regex")
		}
		re = v
		str = re.String()
	default:
		return fmt.Errorf("invalid negation input %s, %T", v, v)
	}
	for i, rv := range r.variables {
		if rv.Variable == v {
			rv.Exceptions = append(rv.Exceptions, ruleVariableException{str, re})
			r.variables[i] = rv
			counter++
		}
	}
	if counter == 0 {
		return fmt.Errorf("cannot create a variable exception is the variable %q is not used", v.Name())
	}
	return nil
}

// AddTransformation adds a transformation to the rule
// it fails if the transformation cannot be found
func (r *Rule) AddTransformation(name string, t RuleTransformation) error {
	if t == nil || name == "" {
		return fmt.Errorf("invalid transformation %q not found", name)
	}
	r.transformations = append(r.transformations, ruleTransformationParams{name, t})
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
func (r *Rule) SetOperator(operator RuleOperator, functionName string, params string) {
	r.operator = &ruleOperatorParams{
		Operator: operator,
		Function: functionName,
		Data:     params,
		Negation: (len(functionName) > 0 && functionName[0] == '!'),
	}
}

func (r *Rule) executeOperator(data string, tx *Transaction) bool {
	result := r.operator.Operator.Evaluate(tx, data)
	if r.operator.Negation && result {
		return false
	}
	if r.operator.Negation && !result {
		return true
	}
	return result
}

func (r *Rule) executeTransformationsMultimatch(value string) ([]string, []error) {
	res := []string{value}
	errs := []error{}
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
	errs := []error{}
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
func NewRule() *Rule {
	return &Rule{
		Phase: 2,
		Tags:  []string{},
	}
}
