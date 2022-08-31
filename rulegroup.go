// Copyright 2022 Juan Pablo Tosso
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
	"time"

	"github.com/corazawaf/coraza/v2/types"
	"github.com/corazawaf/coraza/v2/types/variables"
	"github.com/corazawaf/coraza/v2/utils/strings"
	"go.uber.org/zap"
)

// RuleGroup is a collection of rules
// It contains all helpers required to manage the rules
// It is not concurrent safe, so it's not recommended to use it
// after compilation
type RuleGroup struct {
	rules []*Rule
}

// Add a rule to the collection
// Will return an error if the ID is already used
func (rg *RuleGroup) Add(rule *Rule) error {
	if rule == nil {
		// this is an ugly solution but chains should not return rules
		return nil
	}

	if rg.FindByID(rule.ID) != nil && rule.ID != 0 {
		return fmt.Errorf("there is a another rule with id %d", rule.ID)
	}
	rg.rules = append(rg.rules, rule)
	return nil
}

// GetRules returns the slice of rules,
func (rg *RuleGroup) GetRules() []*Rule {
	return rg.rules
}

// FindByID return a Rule with the requested Id
func (rg *RuleGroup) FindByID(id int) *Rule {
	for _, r := range rg.rules {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// DeleteByID removes a rule by it's Id
func (rg *RuleGroup) DeleteByID(id int) {
	for i, r := range rg.rules {
		if r != nil && r.ID == id {
			copy(rg.rules[i:], rg.rules[i+1:])
			rg.rules[len(rg.rules)-1] = nil
			rg.rules = rg.rules[:len(rg.rules)-1]
		}
	}
}

// FindByMsg returns a slice of rules that matches the msg
func (rg *RuleGroup) FindByMsg(msg string) []*Rule {
	rules := []*Rule{}
	for _, r := range rg.rules {
		if r.Msg.String() == msg {
			rules = append(rules, r)
		}
	}
	return rules
}

// FindByTag returns a slice of rules that matches the tag
func (rg *RuleGroup) FindByTag(tag string) []*Rule {
	rules := []*Rule{}
	for _, r := range rg.rules {
		if strings.InSlice(tag, r.Tags) {
			rules = append(rules, r)
		}
	}
	return rules
}

// Count returns the count of rules
func (rg *RuleGroup) Count() int {
	return len(rg.rules)
}

// Clear will remove each and every rule stored
func (rg *RuleGroup) Clear() {
	rg.rules = []*Rule{}
}

// Eval rules for the specified phase, between 1 and 5
// Returns true if transaction is disrupted
func (rg *RuleGroup) Eval(phase types.RulePhase, tx *Transaction) bool {
	tx.Waf.Logger.Debug("Evaluating phase",
		zap.String("event", "EVALUATE_PHASE"),
		zap.String("txid", tx.ID),
		zap.Int("phase", int(phase)),
	)
	tx.LastPhase = phase
	usedRules := 0
	ts := time.Now().UnixNano()
RulesLoop:
	for _, r := range tx.Waf.Rules.GetRules() {
		if tx.Interruption != nil && phase != types.PhaseLogging {
			break RulesLoop
		}
		// Rules with phase 0 will always run
		if r.Phase != phase && r.Phase != 0 {
			continue
		}

		// we skip the rule in case it's in the excluded list
		for _, trb := range tx.ruleRemoveByID {
			if trb == r.ID {
				tx.Waf.Logger.Debug("Skipping rule", zap.Int("rule", r.ID), zap.String("txid", tx.ID))
				continue RulesLoop
			}
		}

		// we always evaluate secmarkers
		if tx.SkipAfter != "" {
			if r.SecMark == tx.SkipAfter {
				tx.Waf.Logger.Debug("SkipAfter was finished", zap.String("txid", tx.ID),
					zap.String("secmark", r.SecMark),
					zap.String("event", "FINISH_SECMARK"),
				)
				tx.SkipAfter = ""
			} else {
				tx.Waf.Logger.Debug("Skipping rule because of SkipAfter", zap.String("txid", tx.ID),
					zap.Int("rule", r.ID),
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
		// we reset matched_vars, matched_vars_names, etc
		tx.GetCollection(variables.MatchedVars).Reset()
		tx.GetCollection(variables.MatchedVarsNames).Reset()

		r.Evaluate(tx)
		tx.Capture = false // we reset captures
		usedRules++
	}
	tx.Waf.Logger.Debug("Finished phase",
		zap.String("event", "FINISH_PHASE"),
		zap.String("txid", tx.ID),
		zap.Int("phase", int(phase)),
		zap.Int("rules", usedRules),
	)
	tx.stopWatches[phase] = time.Now().UnixNano() - ts
	return tx.Interruption != nil
}

// NewRuleGroup creates an empty RuleGroup that
// can be attached to a WAF instance
// You might use this function to replace the rules
// and "reload" the WAF
func NewRuleGroup() RuleGroup {
	return RuleGroup{
		rules: []*Rule{},
	}
}
