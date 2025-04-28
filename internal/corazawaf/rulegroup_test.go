// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"fmt"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/types"
)

func newTestRule(id int) *Rule {
	r := NewRule()
	r.ID_ = id
	r.Msg, _ = macro.NewMacro("test")
	r.Tags_ = []string{
		"test",
	}
	return r
}

func TestRuleGroupDeleteByTag(t *testing.T) {
	r := newTestRule(1)

	rg := NewRuleGroup()
	if err := rg.Add(r); err != nil {
		t.Error("Failed to add rule to rulegroup")
	}

	if rg.Count() != 1 {
		t.Error("Failed to add rule to rulegroup")
	}

	rg.DeleteByTag("test")
	if rg.Count() != 0 {
		t.Error("Failed to remove rule from rulegroup")
	}
}

func TestRuleGroupDeleteByMsg(t *testing.T) {
	r := newTestRule(1)

	rg := NewRuleGroup()
	if err := rg.Add(r); err != nil {
		t.Error("Failed to add rule to rulegroup")
	}

	if rg.Count() != 1 {
		t.Error("Failed to add rule to rulegroup")
	}

	rg.DeleteByMsg("test")
	if rg.Count() != 0 {
		t.Error("Failed to remove rule from rulegroup")
	}
}

func TestRuleGroupDeleteByID(t *testing.T) {
	var (
		r1 = newTestRule(1)
		r2 = newTestRule(2)
		r3 = newTestRule(3)
		r4 = newTestRule(4)
		r5 = newTestRule(5)
	)

	rg := NewRuleGroup()
	for _, r := range []*Rule{r1, r2, r3, r4, r5} {
		if err := rg.Add(r); err != nil {
			t.Fatalf("Failed to add rule to rulegroup: %s", err.Error())
		}
	}

	if rg.Count() != 5 {
		t.Fatal("Unexpected rules in the rulegroup")
	}

	rg.DeleteByID(1)
	if rg.Count() != 4 {
		t.Fatal("Unexpected remaining rules in the rulegroup")
	}

	rg.DeleteByRange(2, 4)
	if rg.Count() != 1 || rg.GetRules()[0].ID() != 5 {
		t.Fatal("Unexpected remaining rule in the rulegroup")
	}
}

// RuleFilterWrapper provides a flexible way to define rule filtering logic for tests.
type RuleFilterWrapper struct {
	shouldIgnore func(rule types.RuleMetadata) bool
}

func (fw *RuleFilterWrapper) ShouldIgnore(rule types.RuleMetadata) bool {
	if fw.shouldIgnore == nil {
		return false // Default behavior: don't ignore if no function is provided
	}
	return fw.shouldIgnore(rule)
}

// TestRuleFilterInteraction confirms filter is checked first in Eval loop for all phases.
func TestRuleFilterInteraction(t *testing.T) {
	// --- Define Rule (Phase 0 to run in all phases) ---
	rule := NewRule()
	rule.ID_ = 1
	rule.Phase_ = 0     // Phase 0: Always evaluate
	rule.operator = nil // No operator means it always matches
	if err := rule.AddAction("deny", &dummyDenyAction{}); err != nil {
		t.Fatalf("Setup: Failed to add deny action: %v", err)
	}

	// --- Phases to Test ---
	phasesToTest := []types.RulePhase{
		types.PhaseRequestHeaders,
		types.PhaseRequestBody,
		types.PhaseResponseHeaders,
		types.PhaseResponseBody,
		types.PhaseLogging,
	}

	// --- Filter Actions ---
	filterActions := []struct {
		name               string
		filterShouldIgnore bool
		expectInterruption bool // Expect interruption only if filter *allows* the deny rule
	}{
		{
			name:               "Rule Filtered",
			filterShouldIgnore: true,
			expectInterruption: false,
		},
		{
			name:               "Rule Allowed",
			filterShouldIgnore: false,
			expectInterruption: true,
		},
	}

	// --- Iterate through Phases ---
	for _, currentPhase := range phasesToTest {
		phaseTestName := fmt.Sprintf("Phase_%d", currentPhase)

		t.Run(phaseTestName, func(t *testing.T) {
			// --- Iterate through Filter Actions ---
			for _, fa := range filterActions {
				filterActionTestName := fa.name

				t.Run(filterActionTestName, func(t *testing.T) {
					waf := NewWAF()
					if err := waf.Rules.Add(rule); err != nil {
						t.Fatalf("Setup: Failed to add rule for %s/%s: %v", phaseTestName, filterActionTestName, err)
					}
					tx := waf.NewTransaction()

					var filterCalled bool
					testFilter := &RuleFilterWrapper{
						shouldIgnore: func(r types.RuleMetadata) bool {
							filterCalled = true
							return fa.filterShouldIgnore
						},
					}
					tx.SetRuleFilter(testFilter)

					interrupted := waf.Rules.Eval(currentPhase, tx)
					if interrupted != fa.expectInterruption {
						t.Fatalf("[%s/%s] ShouldFilter is '%t', expecting interruption '%t', but Eval returned '%t'",
							phaseTestName, filterActionTestName, fa.filterShouldIgnore, fa.expectInterruption, interrupted,
						)
					}
					if !filterCalled {
						t.Fatalf("[%s/%s] ShouldIgnore was *not* called", phaseTestName, filterActionTestName)
					}
				})
			}
		})
	}
}
