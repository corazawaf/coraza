// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"fmt"
	"time"

	"github.com/corazawaf/coraza/v3/internal/corazatypes"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// RuleGroup is a collection of rules
// It contains all helpers required to manage the rules
// It is not concurrent safe, so it's not recommended to use it
// after compilation
type RuleGroup struct {
	rules []Rule
}

// Add a rule to the collection
// Will return an error if the ID is already used
func (rg *RuleGroup) Add(rule *Rule) error {
	if rule == nil {
		// this is an ugly solution but chains should not return rules
		return nil
	}

	if rule.ID_ != 0 && rg.FindByID(rule.ID_) != nil {
		return fmt.Errorf("there is a another rule with id %d", rule.ID_)
	}

	numInferred := 0
	rule.inferredPhases.set(rule.Phase_)
	for _, v := range rule.variables {
		min := minPhase(v.Variable)
		if min != types.PhaseUnknown {
			// We infer the earliest phase a variable used by the rule may be evaluated for use when
			// multiphase evaluation is enabled
			rule.inferredPhases.set(min)
			numInferred++
		} else {
			rule.withPhaseUnknownVariable = true
		}
	}

	rg.rules = append(rg.rules, *rule)
	return nil
}

// GetRules returns the slice of rules,
func (rg *RuleGroup) GetRules() []Rule {
	return rg.rules
}

// FindByID return a Rule with the requested Id
func (rg *RuleGroup) FindByID(id int) *Rule {
	for i, r := range rg.rules {
		if r.ID_ == id {
			return &rg.rules[i]
		}
	}
	return nil
}

// DeleteByID removes a rule by its ID
func (rg *RuleGroup) DeleteByID(id int) {
	for i, r := range rg.rules {
		if r.ID_ == id {
			rg.rules = append(rg.rules[:i], rg.rules[i+1:]...)
			return
		}
	}
}

// DeleteByRange removes rules by their ID in a range
func (rg *RuleGroup) DeleteByRange(start, end int) {
	var kept []Rule
	for _, r := range rg.rules {
		if r.ID_ < start || r.ID_ > end {
			kept = append(kept, r)
		}
	}
	rg.rules = kept
}

// DeleteByMsg deletes rules with the given message.
func (rg *RuleGroup) DeleteByMsg(msg string) {
	var kept []Rule
	for _, r := range rg.rules {
		if r.Msg.String() != msg {
			kept = append(kept, r)
		}
	}
	rg.rules = kept
}

// DeleteByTag deletes rules with the given tag.
func (rg *RuleGroup) DeleteByTag(tag string) {
	var kept []Rule
	for _, r := range rg.rules {
		if !utils.InSlice(tag, r.Tags_) {
			kept = append(kept, r)
		}
	}
	rg.rules = kept
}

// Count returns the count of rules
func (rg *RuleGroup) Count() int {
	return len(rg.rules)
}

// Eval rules for the specified phase, between 1 and 5
// Rules are evaluated in syntactic order and the evaluation finishes
// as soon as an interruption has been triggered.
// Returns true if transaction is disrupted
func (rg *RuleGroup) Eval(phase types.RulePhase, tx *Transaction) bool {
	tx.DebugLogger().Debug().
		Int("phase", int(phase)).
		Msg("Evaluating phase")

	tx.lastPhase = phase
	usedRules := 0
	ts := time.Now().UnixNano()
	transformationCache := tx.transformationCache
	for k := range transformationCache {
		delete(transformationCache, k)
	}
RulesLoop:
	for i := range rg.rules {
		r := &rg.rules[i]
		// if there is already an interruption and the phase isn't logging
		// we break the loop
		if tx.interruption != nil && phase != types.PhaseLogging {
			break RulesLoop
		}
		// Rules with phase 0 will always run
		if r.Phase_ != 0 && r.Phase_ != phase {
			// Execute the rule in inferred phases too if multiphase evaluation is enabled
			// For chained rules, inferredPhases is not relevant, we rather have to run from minimal potentially
			// matchable phase up to the rule's defined phase (chainMinPhase <= phase <= Phase_)
			// At the first run chainMinPhase is not set, so we look at the parent chain rule's minimal phase.
			// If it is not reached, we skip the whole chain, there is no chance to match it.
			if !multiphaseEvaluation ||
				(!r.HasChain && !r.inferredPhases.has(phase)) ||
				(r.HasChain && phase < r.chainMinPhase) ||
				(r.HasChain && !r.inferredPhases.hasOrMinor(phase) && !r.withPhaseUnknownVariable) ||
				(r.HasChain && phase > r.Phase_) {
				continue
			}
		}

		// we skip the rule in case it's in the excluded list
		for _, trb := range tx.ruleRemoveByID {
			if trb == r.ID_ {
				tx.DebugLogger().Debug().
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
			// Allow phase requires skipping all rules of the current phase.
			// It is done by breaking the loop and resetting AllowType for the next phase right after the loop.
			tx.DebugLogger().Debug().
				Int("phase", int(phase)).
				Msg("Skipping phase because of allow phase action")
			break RulesLoop
		case corazatypes.AllowTypeRequest:
			// Allow request requires skipping all rules of any request phase.
			// It is done by breaking the loop only if in a request phase (1 or 2)
			// and resetting AllowType once the request phases are over (after request body phase)
			tx.DebugLogger().Debug().
				Int("phase", int(phase)).
				Msg("Skipping phase because of allow request action")
			if phase == types.PhaseRequestHeaders {
				// tx.AllowType is not resetted because another request phase might be called
				break RulesLoop
			}
			if phase == types.PhaseRequestBody {
				// // tx.AllowType is resetted, currently PhaseRequestBody is the last request phase
				tx.AllowType = corazatypes.AllowTypeUnset
				break RulesLoop
			}
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
		Int("phase", int(phase)).
		Msg("Finished phase")

	// Reset AllowType if meant to allow only this specific phase. It is particuarly needed
	// to reset it at this point, in case of an allow:phase action enforced by the last rule of the phase.
	// In this case, allow:phase must not have any impact on the next phase.
	if tx.AllowType == corazatypes.AllowTypePhase {
		tx.AllowType = corazatypes.AllowTypeUnset
	}
	// Reset Skip counter at the end of each phase. Skip actions work only within the current processing phase
	tx.Skip = 0

	tx.stopWatches[phase] = time.Now().UnixNano() - ts
	return tx.interruption != nil
}

// NewRuleGroup creates an empty RuleGroup that
// can be attached to a WAF instance
// You might use this function to replace the rules
// and "reload" the WAF
func NewRuleGroup() RuleGroup {
	return RuleGroup{}
}

type transformationKey struct {
	// TODO(anuraaga): This is a big hack to support performance on TinyGo. TinyGo
	// cannot efficiently compute a hashcode for a struct if it has embedded non-fixed
	// size fields, for example string as we'd prefer to use here. A pointer is usable,
	// and it works for us since we know that the arg key string is populated once per
	// transaction phase and we would never have different string pointers with the same
	// content, or more problematically same pointer for different content, as the strings
	// will be alive throughout the phase.
	argKey            *byte
	argIndex          int
	argVariable       variables.RuleVariable
	transformationsID int
}

type transformationValue struct {
	args []string
	errs []error
}
