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
import(
	"errors"
	"fmt"
	"sort"
	"sync"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

type RuleGroup struct{
	rules []*Rule
	mux *sync.RWMutex
}

func (rg *RuleGroup) Init(){
	rg.rules = []*Rule{}
	rg.mux = &sync.RWMutex{}
}

// Adds a rule to the collection
// Will return an error if the ID is already used
func (rg *RuleGroup) Add(rule *Rule) error{
	if rg.FindById(rule.Id) != nil{
		return errors.New(fmt.Sprintf("There is a another rule with ID %d", rule.Id))
	}
	rg.rules = append(rg.rules, rule)
	return nil
}

func (rg *RuleGroup) GetRules() []*Rule{
	rg.mux.RLock()
	defer rg.mux.RUnlock()
	return rg.rules
}

func (rg *RuleGroup) Sort() {
	sort.Slice(rg.rules, func(i, j int) bool {
	  return rg.rules[i].Id < rg.rules[j].Id
	})
}

func (rg *RuleGroup) FindById(id int) *Rule{
	for _, r := range rg.rules{
		if r.Id == id{
			return r
		}
	}
	return nil
}

func (rg *RuleGroup) DeleteById(id int){
	for i, r := range rg.rules{
		if r.Id == id{
			copy(rg.rules[i:], rg.rules[i+1:])
			rg.rules[len(rg.rules)-1] = nil
			rg.rules = rg.rules[:len(rg.rules)-1]
		}
	}
}

func (rg *RuleGroup) FindByMsg(msg string) []*Rule{
	rules := []*Rule{}
	for _, r := range rg.rules{
		if r.Msg == msg{
			rules = append(rules, r)
		}
	}
	return rules
}

func (rg *RuleGroup) FindByTag(tag string) []*Rule{
	rules := []*Rule{}
	for _, r := range rg.rules{
		if utils.StringInSlice(tag, r.Tags) {
			rules = append(rules, r)
		}
	}
	return rules
}

func (rg *RuleGroup) Count() int{
	return len(rg.rules)
}