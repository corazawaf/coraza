// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"fmt"
	"time"

	"github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
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

	if rg.FindByID(rule.ID_) != nil && rule.ID_ != 0 {
		return fmt.Errorf("there is a another rule with id %d", rule.ID_)
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
		if r.ID_ == id {
			return r
		}
	}
	return nil
}

// DeleteByID removes a rule by it's Id
func (rg *RuleGroup) DeleteByID(id int) {
	for i, r := range rg.rules {
		if r != nil && r.ID_ == id {
			copy(rg.rules[i:], rg.rules[i+1:])
			rg.rules[len(rg.rules)-1] = nil
			rg.rules = rg.rules[:len(rg.rules)-1]
		}
	}
}

// FindByMsg returns a slice of rules that matches the msg
func (rg *RuleGroup) FindByMsg(msg string) []*Rule {
	var rules []*Rule
	for _, r := range rg.rules {
		if r.Msg.String() == msg {
			rules = append(rules, r)
		}
	}
	return rules
}

// FindByTag returns a slice of rules that matches the tag
func (rg *RuleGroup) FindByTag(tag string) []*Rule {
	var rules []*Rule
	for _, r := range rg.rules {
		if strings.InSlice(tag, r.Tags_) {
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
	tx.WAF.Logger.Debug("[%s] Evaluating phase %d", tx.id, int(phase))
	tx.LastPhase = phase
	usedRules := 0
	ts := time.Now().UnixNano()
RulesLoop:
	for _, r := range tx.WAF.Rules.GetRules() {
		if tx.interruption != nil && phase != types.PhaseLogging {
			break RulesLoop
		}
		// Rules with phase 0 will always run
		if r.Phase_ != phase && r.Phase_ != 0 {
			continue
		}

		// we skip the rule in case it's in the excluded list
		for _, trb := range tx.ruleRemoveByID {
			if trb == r.ID_ {
				tx.WAF.Logger.Debug("[%s] Skipping rule %d", tx.id, r.ID_)
				continue RulesLoop
			}
		}

		// we always evaluate secmarkers
		if tx.SkipAfter != "" {
			if r.SecMark_ == tx.SkipAfter {
				tx.SkipAfter = ""
			} else {
				tx.WAF.Logger.Debug("[%s] Skipping rule %d because of SkipAfter, expecting %s and got: %q", tx.id, r.ID_, tx.SkipAfter, r.SecMark_)
			}
			continue
		}
		if tx.Skip > 0 {
			tx.Skip--
			// Skipping rule
			continue
		}
		// TODO this lines are SUPER SLOW
		// we reset matched_vars, matched_vars_names, etc
		tx.variables.matchedVars.Reset()
		tx.variables.matchedVarsNames.Reset()

		r.Evaluate(tx)
		tx.Capture = false // we reset captures
		usedRules++
	}
	tx.WAF.Logger.Debug("[%s] Finished phase %d", tx.id, int(phase))
	tx.stopWatches[phase] = time.Now().UnixNano() - ts
	return tx.interruption != nil
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
