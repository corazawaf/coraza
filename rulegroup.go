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
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/jptosso/coraza-waf/v2/types"
	"github.com/jptosso/coraza-waf/v2/types/variables"
	"github.com/jptosso/coraza-waf/v2/utils/strings"
	"go.uber.org/zap"
)

type ruleGroup struct {
	rules []*Rule
	mux   *sync.RWMutex
}

// Adds a rule to the collection
// Will return an error if the ID is already used
func (rg *ruleGroup) Add(rule *Rule) error {
	if rule == nil {
		// this is an ugly solution but chains should not return rules
		return nil
	}

	if rg.FindById(rule.Id) != nil && rule.Id != 0 {
		return fmt.Errorf("there is a another rule with id %d", rule.Id)
	}
	rg.rules = append(rg.rules, rule)
	return nil
}

// GetRules returns the slice of rules,
// it's concurrent safe.
func (rg *ruleGroup) GetRules() []*Rule {
	rg.mux.RLock()
	defer rg.mux.RUnlock()
	return rg.rules
}

// FindById return a Rule with the requested Id
func (rg *ruleGroup) FindById(id int) *Rule {
	for _, r := range rg.rules {
		if r.Id == id {
			return r
		}
	}
	return nil
}

// DeleteById removes a rule by it's Id
func (rg *ruleGroup) DeleteById(id int) {
	for i, r := range rg.rules {
		if r != nil && r.Id == id {
			copy(rg.rules[i:], rg.rules[i+1:])
			rg.rules[len(rg.rules)-1] = nil
			rg.rules = rg.rules[:len(rg.rules)-1]
		}
	}
}

// FindByMsg returns a slice of rules that matches the msg
func (rg *ruleGroup) FindByMsg(msg string) []*Rule {
	rules := []*Rule{}
	for _, r := range rg.rules {
		if r.Msg == msg {
			rules = append(rules, r)
		}
	}
	return rules
}

// FindByTag returns a slice of rules that matches the tag
func (rg *ruleGroup) FindByTag(tag string) []*Rule {
	rules := []*Rule{}
	for _, r := range rg.rules {
		if strings.StringInSlice(tag, r.Tags) {
			rules = append(rules, r)
		}
	}
	return rules
}

// Count returns the count of rules
func (rg *ruleGroup) Count() int {
	return len(rg.rules)
}

// Clear will remove each and every rule stored
func (rg *ruleGroup) Clear() {
	rg.rules = []*Rule{}
}

// Eval rules for the specified phase, between 1 and 5
// Returns true if transaction is disrupted
func (rg *ruleGroup) Eval(phase types.RulePhase, tx *Transaction) bool {
	tx.Waf.Logger.Debug("Evaluating phase",
		zap.String("event", "EVALUATE_PHASE"),
		zap.String("txid", tx.Id),
		zap.Int("phase", int(phase)),
	)
	tx.LastPhase = phase
	usedRules := 0
	ts := time.Now().UnixNano()
RulesLoop:
	for _, r := range tx.Waf.Rules.GetRules() {
		if tx.Interruption != nil {
			tx.Waf.Logger.Debug("Finished phase",
				zap.String("event", "FINISH_PHASE"),
				zap.String("txid", tx.Id),
				zap.Int("phase", int(phase)),
				zap.Int("rules", usedRules),
			)
			return true
		}
		// Rules with phase 0 will always run
		if r.Phase != phase && r.Phase != 0 {
			continue
		}
		rid := strconv.Itoa(r.Id)
		if r.Id == 0 {
			rid = strconv.Itoa(r.ParentId)
		}

		// we skip the rule in case it's in the excluded list
		for _, trb := range tx.ruleRemoveById {
			if trb == r.Id {
				tx.Waf.Logger.Debug("Skipping rule", zap.Int("rule", r.Id), zap.String("txid", tx.Id))
				continue RulesLoop
			}
		}

		// we always evaluate secmarkers
		if tx.SkipAfter != "" {
			if r.SecMark == tx.SkipAfter {
				tx.Waf.Logger.Debug("SkipAfter was finished", zap.String("txid", tx.Id),
					zap.String("secmark", r.SecMark),
					zap.String("event", "FINISH_SECMARK"),
				)
				tx.SkipAfter = ""
			} else {
				tx.Waf.Logger.Debug("Skipping rule because of SkipAfter", zap.String("txid", tx.Id),
					zap.Int("rule", r.Id),
					zap.String("secmark", tx.SkipAfter),
					zap.String("event", "SKIP_RULE_BY_SECMARK"),
				)
			}
			continue
		}
		if tx.Skip > 0 {
			tx.Skip--
			// Skipping rule
			continue
		}
		// we reset captures, matched_vars, matched_vars_names, etc
		tx.resetAfterRule()

		txr := tx.GetCollection(variables.Rule)
		txr.Set("id", []string{rid})
		txr.Set("rev", []string{r.Rev})
		txr.Set("severity", []string{r.Severity.String()})
		txr.Set("logdata", []string{r.LogData})
		txr.Set("msg", []string{r.Msg})
		r.Evaluate(tx)
		usedRules++
	}
	tx.Waf.Logger.Debug("Finished phase",
		zap.String("event", "FINISH_PHASE"),
		zap.String("txid", tx.Id),
		zap.Int("phase", int(phase)),
		zap.Int("rules", usedRules),
	)
	tx.StopWatches[phase] = int(time.Now().UnixNano() - ts)
	return tx.Interruption != nil
}

func NewRuleGroup() ruleGroup {
	return ruleGroup{
		rules: []*Rule{},
		mux:   &sync.RWMutex{},
	}
}
