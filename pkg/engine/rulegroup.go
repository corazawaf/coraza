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

package engine

import (
	"errors"
	"fmt"
	"github.com/jptosso/coraza-waf/pkg/utils"
	"strconv"
	"sync"
	"time"
)

type RuleGroup struct {
	rules []*Rule
	mux   *sync.RWMutex
}

// Adds a rule to the collection
// Will return an error if the ID is already used
func (rg *RuleGroup) Add(rule *Rule) error {
	if rule == nil {
		// this is an ugly solution but chains should not return rules
		return nil
	}
	if rg.FindById(rule.Id) != nil && rule.Id != 0 {
		return errors.New(fmt.Sprintf("There is a another rule with ID %d", rule.Id))
	}
	rg.rules = append(rg.rules, rule)
	return nil
}

func (rg *RuleGroup) GetRules() []*Rule {
	rg.mux.RLock()
	defer rg.mux.RUnlock()
	return rg.rules
}

func (rg *RuleGroup) Sort() {
	// Apparently rules shouldn't be sorted
	/*
		sort.Slice(rg.rules, func(i, j int) bool {
			return rg.rules[i].Id < rg.rules[j].Id
		})*/
}

func (rg *RuleGroup) FindById(id int) *Rule {
	for _, r := range rg.rules {
		if r.Id == id {
			return r
		}
	}
	return nil
}

func (rg *RuleGroup) DeleteById(id int) {
	for i, r := range rg.rules {
		if r.Id == id {
			copy(rg.rules[i:], rg.rules[i+1:])
			rg.rules[len(rg.rules)-1] = nil
			rg.rules = rg.rules[:len(rg.rules)-1]
		}
	}
}

func (rg *RuleGroup) FindByMsg(msg string) []*Rule {
	rules := []*Rule{}
	for _, r := range rg.rules {
		if r.Msg == msg {
			rules = append(rules, r)
		}
	}
	return rules
}

func (rg *RuleGroup) FindByTag(tag string) []*Rule {
	rules := []*Rule{}
	for _, r := range rg.rules {
		if utils.StringInSlice(tag, r.Tags) {
			rules = append(rules, r)
		}
	}
	return rules
}

func (rg *RuleGroup) Count() int {
	return len(rg.rules)
}

func (rg *RuleGroup) Clear() {
	rg.rules = []*Rule{}
}

// Execute rules for the specified phase, between 1 and 5
// Returns true if transaction is disrupted
func (rg *RuleGroup) Evaluate(phase int, tx *Transaction) bool {
	tx.LastPhase = phase
	ts := time.Now().UnixNano()
	usedRules := 0
	tx.LastPhase = phase
	for _, r := range tx.Waf.Rules.GetRules() {
		// Rules with phase 0 will always run
		if r.Phase != phase && r.Phase != 0 {
			continue
		}
		rid := strconv.Itoa(r.Id)
		if r.Id == 0 {
			rid = strconv.Itoa(r.ParentId)
		}
		if utils.ArrayContainsInt(tx.RuleRemoveById, r.Id) {
			continue
		}
		//we always evaluate secmarkers
		if tx.SkipAfter != "" {
			if r.SecMark == tx.SkipAfter {
				tx.SkipAfter = ""
			}
			continue
		}
		if tx.Skip > 0 {
			tx.Skip--
			//Skipping rule
			continue
		}
		txr := tx.GetCollection(VARIABLE_RULE)
		txr.Set("id", []string{rid})
		txr.Set("rev", []string{r.Rev})
		txr.Set("severity", []string{r.Severity})
		//txr.Set("logdata", []string{r.LogData})
		txr.Set("msg", []string{r.Msg})
		r.Evaluate(tx)

		tx.Capture = false //we reset the capture flag on every run
		usedRules++
	}
	tx.StopWatches[phase] = int(time.Now().UnixNano() - ts)
	return tx.Interruption != nil
}

func NewRuleGroup() *RuleGroup{
	return &RuleGroup {
		rules: []*Rule{},
		mux: &sync.RWMutex{},
	}	
}