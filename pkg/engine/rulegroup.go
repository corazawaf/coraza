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
	//"sort"
	"sync"
)

type RuleGroup struct {
	// rules per phase
	rules map[int][]*Rule
	mux   *sync.RWMutex
}

func (rg *RuleGroup) Init() {
	rg.rules = map[int][]*Rule{}
	rg.mux = &sync.RWMutex{}
}

// Adds a rule to the collection
// Will return an error if the ID is already used
func (rg *RuleGroup) Add(rule *Rule) error {
	if rule == nil {
		// this is an ugly solution but chains should not return rules
		return nil
	}
	phase := rule.Phase
	if phase < 0 || phase > 5 {
		return errors.New("Invalid phase")
	}
	if rule.Id != 0 && rg.FindById(rule.Id) != nil {
		return errors.New(fmt.Sprintf("There is a another rule with ID %d", rule.Id))
	}
	rg.rules[phase] = append(rg.rules[phase], rule)
	return nil
}

func (rg *RuleGroup) GetRules(phase int) []*Rule {
	rg.mux.RLock()
	defer rg.mux.RUnlock()
	return rg.rules[phase]
}

func (rg *RuleGroup) GetAllRules() []*Rule {
	rg.mux.RLock()
	defer rg.mux.RUnlock()
	rules := []*Rule{}
	for _, r := range rg.rules {
		rules = append(rules, r...)
	}
	return rules
}

func (rg *RuleGroup) Sort() {
	// Apparently rules shouldn't be sorted
	/*
		sort.Slice(rg.rules, func(i, j int) bool {
			return rg.rules[i].Id < rg.rules[j].Id
		})*/
}

func (rg *RuleGroup) FindById(id int) *Rule {
	for p, _ := range rg.rules {
		for _, r := range rg.rules[p] {
			if r.Id == id {
				return r
			}
		}
	}
	return nil
}

func (rg *RuleGroup) DeleteById(id int) {
	for p, _ := range rg.rules {
		for i, r := range rg.rules[p] {
			if r.Id == id {
				copy(rg.rules[p][i:], rg.rules[p][i+1:])
				rg.rules[p][len(rg.rules[p])-1] = nil
				rg.rules[p] = rg.rules[p][:len(rg.rules[p])-1]
			}
		}
	}
}

func (rg *RuleGroup) FindByMsg(msg string) []*Rule {
	rules := []*Rule{}
	for p, _ := range rg.rules {
		for _, r := range rg.rules[p] {
			if r.Msg == msg {
				rules = append(rules, r)
			}
		}
	}
	return rules
}

func (rg *RuleGroup) FindByTag(tag string) []*Rule {
	rules := []*Rule{}
	for p, _ := range rg.rules {
		for _, r := range rg.rules[p] {
			if utils.StringInSlice(tag, r.Tags) {
				rules = append(rules, r)
			}
		}
	}
	return rules
}

func (rg *RuleGroup) Count() int {
	c := 0
	for _, r := range rg.rules {
		c += len(r)
	}
	return c
}

func (rg *RuleGroup) Clear() {
	rg.rules = map[int][]*Rule{}
}
