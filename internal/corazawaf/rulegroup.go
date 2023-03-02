// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"fmt"
	"time"

	"github.com/corazawaf/coraza/v3/internal/corazatypes"
	"github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
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

	numInferred := 0
	rule.inferredPhases[rule.Phase_] = true
	for _, v := range rule.variables {
		min := minPhase(v.Variable)
		if min != 0 {
			// We infer the earliest phase a variable used by the rule may be evaluated for use when
			// multiphase evaluation is enabled
			rule.inferredPhases[min] = true
			numInferred++
		}
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
// Rules are evaluated in syntactic order and the evaluation finishes
// as soon as an interruption has been triggered.
// Returns true if transaction is disrupted
func (rg *RuleGroup) Eval(phase types.RulePhase, tx *Transaction) bool {
	tx.DebugLogger().Debug().
		Str("tx_id", tx.id).
		Int("phase", int(phase)).
		Msg("Evaluating phase")

	tx.LastPhase = phase
	usedRules := 0
	ts := time.Now().UnixNano()
	transformationCache := tx.transformationCache
	for k := range transformationCache {
		delete(transformationCache, k)
	}
RulesLoop:
	for _, r := range tx.WAF.Rules.GetRules() {
		// if there is already an interruption and the phase isn't logging
		// we break the loop
		if tx.interruption != nil && phase != types.PhaseLogging {
			break RulesLoop
		}
		// Rules with phase 0 will always run
		if r.Phase_ != 0 && r.Phase_ != phase {
			// Execute the rule in inferred phases too if multiphase evaluation is enabled
			if !multiphaseEvaluation || !r.inferredPhases[phase] {
				continue
			}
		}

		// we skip the rule in case it's in the excluded list
		for _, trb := range tx.ruleRemoveByID {
			if trb == r.ID_ {
				tx.DebugLogger().Debug().
					Str("tx_id", tx.id).
					Int("rule_id", r.ID_).
					Msg("Skipping rule")

				continue RulesLoop
			}
		}

		// we always evaluate secmarkers
		if tx.SkipAfter != "" {
			if r.SecMark_ == tx.SkipAfter {
				tx.SkipAfter = ""
			} else {
				tx.DebugLogger().Debug().
					Str("tx_id", tx.id).
					Int("rule_id", r.ID_).
					Str("skip_after", tx.SkipAfter).
					Str("secmarker", r.SecMark_).
					Msg("Skipping rule because of SkipAfter")
			}
			continue
		}
		if tx.Skip > 0 {
			tx.Skip--
			// Skipping rule
			continue
		}
		switch tx.AllowType {
		case corazatypes.AllowTypeUnset:
			break
		case corazatypes.AllowTypePhase:
			tx.AllowType = corazatypes.AllowTypeUnset
			continue RulesLoop
		case corazatypes.AllowTypeRequest:
			tx.AllowType = corazatypes.AllowTypeUnset
			break RulesLoop
		case corazatypes.AllowTypeAll:
			break RulesLoop
		}
		// TODO these lines are SUPER SLOW
		// we reset matched_vars, matched_vars_names, etc
		tx.variables.matchedVars.Reset()

		r.Evaluate(phase, tx, transformationCache)
		tx.Capture = false // we reset captures
		usedRules++
	}
	tx.DebugLogger().Debug().
		Str("tx_id", tx.id).
		Int("phase", int(phase)).
		Msg("Finished phase")

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

type transformationKey struct {
	// TODO(anuraaga): This is a big hack to support performance on TinyGo. TinyGo
	// cannot efficiently compute a hashcode for a struct if it has embedded non-fixed
	// size fields, for example string as we'd prefer to use here. A pointer is usable,
	// and it works for us since we know that the arg key string is populated once per
	// transaction phase and we would never have different string pointers with the same
	// content, or more problematically same pointer for different content, as the strings
	// will be alive throughout the phase.
	argKey            uintptr
	argIndex          int
	argVariable       variables.RuleVariable
	transformationsID int
}

type transformationValue struct {
	args []string
	errs []error
}
