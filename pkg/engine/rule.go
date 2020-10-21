// Copyright 2020 Juan Pablo Tosso
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

package engine

import (
	_ "github.com/sirupsen/logrus"
	"reflect"
	"strconv"
	"sync"
)

const (
	ACTION_TYPE_METADATA      = 1
	ACTION_TYPE_DISRUPTIVE    = 2
	ACTION_TYPE_DATA          = 3
	ACTION_TYPE_NONDISRUPTIVE = 4
	ACTION_TYPE_FLOW          = 5

	ACTION_DISRUPTIVE_PASS     = 0
	ACTION_DISRUPTIVE_DROP     = 1
	ACTION_DISRUPTIVE_BLOCK    = 2
	ACTION_DISRUPTIVE_DENY     = 3
	ACTION_DISRUPTIVE_ALLOW    = 4
	ACTION_DISRUPTIVE_PROXY    = 5
	ACTION_DISRUPTIVE_REDIRECT = 6
)

type Action interface {
	Init(*Rule, string) string
	Evaluate(*Rule, *Transaction)
	GetType() int
}

type Operator interface {
	Init(string)
	Evaluate(*Transaction, string) bool
}

type RuleOp struct {
	Operator Operator
	Data     string
	Negation bool
	//OpEval OperatorFunction
}

type RuleTransformation struct {
	Function string
	TfFunc   interface{} `json:"-"`
}

type RuleVariable struct {
	Count      bool
	Collection string
	Key        string
	Exceptions []string
}

type Rule struct {
	// Contains de non-compiled variables part of the rule
	Vars string `json:"vars"`

	Variables               []RuleVariable       `json:"variables"`
	Operator                string               `json:"operator"`
	OperatorObj             *RuleOp              `json:"operator_obj"`
	Disruptive              bool                 `json:"disruptive"`
	Transformations         []RuleTransformation `json:"transformations"`
	HasChain                bool                 `json:"has_chain"`
	ParentId                int                  `json:"parent_id"`
	Actions                 []Action             `json:"actions"`
	ActionParams            string               `json:"action_params"`
	MultiMatch              bool                 `json:"multimatch"`
	Severity                string               `json:"severity"`
	Skip                    bool                 `json:"skip"`
	SecMark                 string               `json:"secmark"`
	Log                     bool                 `json:"log"`
	Raw                     string               `json:"raw"`
	Chain                   *Rule                `json:"chain"`
	DisruptiveAction        int                  `json:"disruptive_action"`
	DefaultDisruptiveAction string               `json:"default_disruptive_action"`

	//METADATA
	// Rule unique sorted identifier
	Id int `json:"id"`

	// Rule tag list
	Tags []string `json:"tags"`

	// Rule execution phase 1-5
	Phase int `json:"phase"`

	// Message text to be macro expanded and logged
	Msg string `json:"msg"`

	// Rule revision value
	Rev string `json:"rev"`

	// Rule maturity index
	Maturity string `json:"maturity"`

	// Rule Set Version
	Version string `json:"version"`

	mux *sync.RWMutex
}

func (r *Rule) Init() {
	r.Phase = 1
	r.Tags = []string{}
	r.mux = &sync.RWMutex{}
}

func (r *Rule) Evaluate(tx *Transaction) []*MatchData {
	matchedValues := []*MatchData{}
	for _, nid := range tx.RuleRemoveById {
		if nid == r.Id {
			return matchedValues
		}
	}
	ecol := tx.GetRemovedTargets(r.Id)
	for _, v := range r.Variables {
		var values []*MatchData
		exceptions := make([]string, len(v.Exceptions))
		copy(exceptions, v.Exceptions)
		if ecol != nil {
			for _, c := range ecol {
				if c.Name == v.Collection {
					exceptions = append(exceptions, c.Key)
				}
			}
		}

		values = tx.GetField(v.Collection, v.Key, exceptions)
		if v.Count {
			if v.Key != "" && len(values) == 1 {
				values[0].Value = strconv.Itoa(len(values[0].Value))
			} else {
				values = []*MatchData{
					&MatchData{
						Collection: v.Collection,
						Key:        v.Key,
						Value:      strconv.Itoa(len(values)),
					},
				}
			}
		}

		if len(values) == 0 {
			if r.executeOperator("", tx) {
				matchedValues = append(matchedValues, &MatchData{})
			}
			continue
		}
		for _, arg := range values {
			var args []string
			if r.MultiMatch {
				args = r.executeTransformationsMultimatch(arg.Value)
			} else {
				args = []string{r.executeTransformations(arg.Value)}
			}
			for _, carg := range args {
				if r.executeOperator(carg, tx) {
					matchedValues = append(matchedValues, &MatchData{
						Collection: arg.Collection,
						Key:        arg.Key,
						Value:      carg,
					})
				}
			}
		}
	}

	if len(matchedValues) == 0 {
		//No match for variables
		return matchedValues
	}
	tx.MatchVars(matchedValues)

	// We run non disruptive actions even if there is no chain match
	for _, a := range r.Actions {
		if a.GetType() != ACTION_TYPE_NONDISRUPTIVE {
			continue
		}
		a.Evaluate(r, tx)
	}

	tx.SetCapturable(false)

	msgs := []string{tx.MacroExpansion(r.Msg)}
	if r.Chain != nil {
		nr := r.Chain
		for nr != nil {
			m := nr.Evaluate(tx)
			if len(m) == 0 {
				//we fail the chain
				return []*MatchData{}
			}
			msgs = append(msgs, tx.MacroExpansion(nr.Msg))

			for _, child := range m {
				matchedValues = append(matchedValues, child)
			}
			nr = nr.Chain
		}
	}
	if r.ParentId == 0 {
		if r.Log {
			tx.MatchRule(r, msgs, matchedValues)
		}
		//we need to add disruptive actions in the end, otherwise they would be triggered without their chains.
		for _, a := range r.Actions {
			if a.GetType() == ACTION_TYPE_DISRUPTIVE || a.GetType() == ACTION_TYPE_FLOW {
				a.Evaluate(r, tx)
			}
		}
	}
	return matchedValues
}

func (r *Rule) executeOperator(data string, tx *Transaction) bool {
	result := r.OperatorObj.Operator.Evaluate(tx, data)
	if r.OperatorObj.Negation && result {
		return false
	}
	if r.OperatorObj.Negation && !result {
		return true
	}
	return result
}

func (r *Rule) executeTransformationsMultimatch(value string) []string {
	res := []string{value}
	for _, t := range r.Transformations {
		rf := reflect.ValueOf(t.TfFunc)
		rargs := make([]reflect.Value, 1)
		rargs[0] = reflect.ValueOf(value)
		call := rf.Call(rargs)
		value = call[0].String()
		res = append(res, value)
	}
	return res
}

func (r *Rule) executeTransformations(value string) string {
	for _, t := range r.Transformations {
		rf := reflect.ValueOf(t.TfFunc)
		rargs := make([]reflect.Value, 1)
		rargs[0] = reflect.ValueOf(value)
		call := rf.Call(rargs)
		value = call[0].String()
	}
	return value
}

func (r *Rule) AddVariable(count bool, collection string, key string) {
	rv := RuleVariable{count, collection, key, []string{}}
	r.Variables = append(r.Variables, rv)
}

func (r *Rule) AddNegateVariable(collection string, key string) {
	for i, vr := range r.Variables {
		if vr.Collection == collection {
			vr.Exceptions = append(vr.Exceptions, key)
			r.Variables[i] = vr
			return
		}
	}
}

func NewRule() *Rule {
	r := &Rule{}
	r.Init()
	return r
}
