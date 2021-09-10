// Copyright 2021 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package coraza

import (
	"strconv"

	"github.com/jptosso/coraza-waf/transformations"
	"github.com/jptosso/coraza-waf/utils/regex"
	"go.uber.org/zap"
)

const (
	ACTION_TYPE_METADATA      = 1
	ACTION_TYPE_DISRUPTIVE    = 2
	ACTION_TYPE_DATA          = 3
	ACTION_TYPE_NONDISRUPTIVE = 4
	ACTION_TYPE_FLOW          = 5
)

// This interface is used by this rule's actions
type RuleAction interface {
	// Initializes an action, will be done during compilation
	Init(*Rule, string) error
	// Evaluate will be done during rule evaluation
	Evaluate(*Rule, *Transaction)
	// Type will return the rule type, it's used by Evaluate
	// to choose when to evaluate each action
	Type() int
}

// Operator interface is used to define rule @operators
type Operator interface {
	// Init is used during compilation to setup and cache
	// the operator
	Init(string) error
	// Evaluate is used during the rule evaluation,
	// it returns true if the operator succeeded against
	// the input data for the transaction
	Evaluate(*Transaction, string) bool
}

// RuleOperator is a container for an operator,
type RuleOperator struct {
	// Operator to be used
	Operator Operator
	// Data to initialize the operator
	Data string
	// If true, rule will match if op.Evaluate returns false
	Negation bool
}

// RuleVariable is compiled during runtime by transactions
// to get values from the transaction's variables
// It supports xml, regex, exceptions and many more features
type RuleVariable struct {
	// If true, the count of results will be returned
	Count bool

	// The VARIABLE that will be requested
	Collection byte

	// The key for the variable that is going to be requested
	Key string

	// If not nil, a regex will be used instead of a key
	Regex *regex.Regexp //for performance

	// A slice of key exceptions
	Exceptions []string
}

// Rule is used to test a Transaction against certain operators
// and execute actions
type Rule struct {
	// Contains a list of variables that will be compiled
	// by a transaction
	Variables []RuleVariable

	// Contains a pointer to the Operator struct used
	// SecActions and SecMark can have nil Operators
	Operator *RuleOperator

	// List of transformations to be evaluated
	// In the future, transformations might be run by the
	// action itself
	Transformations []transformations.Transformation

	// Contains the Id of the parent rule if you are inside
	// a chain. Otherwise it will be 0
	ParentId int

	// Slice of initialized actions to be evaluated during
	// the rule evaluation process
	Actions []RuleAction

	// Used to mark a rule as a secmarker and alter flows
	SecMark string

	// Contains the raw rule code
	Raw string

	// Contains the child rule to chain, nil if there are no chains
	Chain *Rule

	// Used by the chain action to indicate if the next rule is chained
	// to this one, it's only used for compilation
	HasChain bool

	// If true, this rule will always match and won't run it's operator
	AlwaysMatch bool

	// Where is this rule stored
	File string

	// Line of the file where this rule was found
	Line int

	//METADATA
	// Rule unique sorted identifier
	Id int

	// Rule tag list
	Tags []string

	// Rule execution phase 1-5
	Phase Phase

	// Message text to be macro expanded and logged
	Msg string

	// Rule revision value
	Rev string

	// Rule maturity index
	Maturity int

	// RuleSet Version
	Version string

	// Rule accuracy
	Accuracy int

	// Rule severity
	Severity int

	// Rule logdata
	LogData string

	// If true and this rule is matched, this rule will be
	// written to the audit log
	// If no auditlog, this rule won't be logged
	Log bool

	// If true, the transformations will be multimatched
	MultiMatch bool
}

// Evaluate will evaluate the current rule for the indicated transaction
// If the operator matches, actions will be evaluated and it will return
// the matched variables, keys and values (MatchData)
func (r *Rule) Evaluate(tx *Transaction) []MatchData {
	tx.Waf.Logger.Debug("Evaluating rule",
		zap.Int("rule", r.Id),
		zap.String("tx", tx.Id),
		zap.String("event", "EVALUATE_RULE"),
	)
	matchedValues := []MatchData{}
	for _, nid := range tx.RuleRemoveById {
		if nid == r.Id {
			//This rules will be skipped
			return matchedValues
		}
	}
	tx.GetCollection(VARIABLE_RULE).SetData(map[string][]string{
		"id":       {strconv.Itoa(r.Id)},
		"msg":      {r.Msg},
		"rev":      {r.Rev},
		"logdata":  {tx.MacroExpansion(r.LogData)},
		"severity": {strconv.Itoa(r.Severity)},
	})
	// secmarkers and secactions will always match
	if r.Operator == nil {
		tx.Waf.Logger.Debug("Forcing rule match", zap.String("txid", tx.Id),
			zap.Int("rule", r.Id),
			zap.String("event", "RULE_FORCE_MATCH"),
		)
		matchedValues = []MatchData{
			{
				Collection: "none",
				Key:        "",
				Value:      "",
			},
		}
	}
	tools := &transformations.Tools{
		Unicode: tx.Waf.Unicode,
		Logger:  tx.Waf.Logger,
	}

	ecol := tx.RuleRemoveTargetById[r.Id]
	for _, v := range r.Variables {
		var values []MatchData
		exceptions := make([]string, len(v.Exceptions))
		copy(exceptions, v.Exceptions)
		for _, c := range ecol {
			if c.Collection == v.Collection {
				exceptions = append(exceptions, c.Key)
			}
		}

		if v.Count {
			l := 0
			if v.Key != "" {
				//Get with macro expansion
				values = tx.GetField(v, exceptions)
				l = len(values)
			} else {
				l = len(tx.GetCollection(v.Collection).Data())
			}
			values = []MatchData{
				{
					Collection: VariableToName(v.Collection),
					Key:        v.Key,
					Value:      strconv.Itoa(l),
				},
			}
		} else {
			values = tx.GetField(v, exceptions)
		}

		if r.AlwaysMatch {
			matchedValues = append(matchedValues, MatchData{
				// TODO add something here?
			})
			continue
		}
		if len(values) == 0 {
			// TODO should we run the operators here?
			continue
		}
		tx.Waf.Logger.Debug("Arguments expanded",
			zap.Int("rule", r.Id),
			zap.String("tx", tx.Id),
			zap.Int("count", len(values)),
		)
		for _, arg := range values {
			var args []string
			if r.MultiMatch {
				// TODO in the future, we don't need to run every transformation
				// We can try for each until found
				args = r.executeTransformationsMultimatch(arg.Value, tools)
			} else {
				args = []string{r.executeTransformations(arg.Value, tools)}
			}
			tx.Waf.Logger.Debug("arguments transformed",
				zap.Int("rule", r.Id),
				zap.String("tx", tx.Id),
				zap.Strings("arguments", args),
			)

			for _, carg := range args {
				match := r.executeOperator(carg, tx)
				if match {
					matchedValues = append(matchedValues, MatchData{
						Collection: arg.Collection,
						Key:        arg.Key,
						Value:      carg,
					})
				}
				tx.Waf.Logger.Debug("Evaluate rule operator", zap.String("txid", tx.Id),
					zap.Int("rule", r.Id),
					zap.String("event", "EVALUATE_RULE_OPERATOR"),
					zap.String("operator", "nn"), //TODO fix
					zap.String("data", carg),
					zap.String("variable", arg.Collection),
					zap.String("key", arg.Key),
					zap.Bool("result", match),
				)
			}
		}
	}

	if len(matchedValues) == 0 {
		//No match for variables
		return matchedValues
	}

	// we must match the vars before runing the chains
	tx.MatchVars(matchedValues)

	// We run non disruptive actions even if there is no chain match
	for _, a := range r.Actions {
		if a.Type() == ACTION_TYPE_NONDISRUPTIVE {
			a.Evaluate(r, tx)
		}
	}

	// We reset the capturable configuration
	tx.Capture = false

	msgs := []string{tx.MacroExpansion(r.Msg)}
	if r.Chain != nil {
		nr := r.Chain
		for nr != nil {
			m := nr.Evaluate(tx)
			if len(m) == 0 {
				//we fail the chain
				return []MatchData{}
			}
			msgs = append(msgs, tx.MacroExpansion(nr.Msg))

			matchedValues = append(matchedValues, m...)
			nr = nr.Chain
		}
	}
	if r.ParentId == 0 {
		// action log is required to add the rule to matched rules
		if r.Log {
			tx.MatchRule(*r, msgs, matchedValues)
		}
		//we need to add disruptive actions in the end, otherwise they would be triggered without their chains.
		tx.Waf.Logger.Debug("detecting rule disruptive action", zap.String("txid", tx.Id), zap.Int("rule", r.Id))
		for _, a := range r.Actions {
			if a.Type() == ACTION_TYPE_DISRUPTIVE || a.Type() == ACTION_TYPE_FLOW {
				tx.Waf.Logger.Debug("evaluating rule disruptive action", zap.String("txid", tx.Id), zap.Int("rule", r.Id))
				a.Evaluate(r, tx)
			}
		}
	}
	tx.Waf.Logger.Debug("finished evaluating rule", zap.String("txid", tx.Id),
		zap.Int("rule", r.Id),
		zap.Int("matched_values", len(matchedValues)),
		zap.String("event", "FINISH_RULE"),
	)
	return matchedValues
}

func (r *Rule) executeOperator(data string, tx *Transaction) bool {
	result := r.Operator.Operator.Evaluate(tx, data)
	if r.Operator.Negation && result {
		return false
	}
	if r.Operator.Negation && !result {
		return true
	}
	return result
}

func (r *Rule) executeTransformationsMultimatch(value string, tools *transformations.Tools) []string {
	res := []string{value}
	for _, t := range r.Transformations {
		value = t(value, tools)
		res = append(res, value)
	}
	return res
}

func (r *Rule) executeTransformations(value string, tools *transformations.Tools) string {
	for _, t := range r.Transformations {
		value = t(value, tools)
	}
	return value
}

// NewRule returns a new initialized rule
func NewRule() *Rule {
	return &Rule{
		Phase: 2,
		Tags:  []string{},
	}
}
