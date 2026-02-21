// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
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

func TestRuleGroupMerge(t *testing.T) {
	rg1 := NewRuleGroup()
	if err := rg1.Add(newTestRule(1)); err != nil {
		t.Fatal(err)
	}
	if err := rg1.Add(newTestRule(2)); err != nil {
		t.Fatal(err)
	}

	rg2 := NewRuleGroup()
	if err := rg2.Add(newTestRule(3)); err != nil {
		t.Fatal(err)
	}

	if err := rg1.Merge(&rg2); err != nil {
		t.Fatal(err)
	}
	if rg1.Count() != 3 {
		t.Fatalf("expected 3 rules after merge, got %d", rg1.Count())
	}
	// Source should be unchanged
	if rg2.Count() != 1 {
		t.Fatalf("expected source to still have 1 rule, got %d", rg2.Count())
	}
}

func TestRuleGroupMergeSecAction(t *testing.T) {
	rg1 := NewRuleGroup()
	// SecAction rules have ID 0
	if err := rg1.Add(newTestRule(0)); err != nil {
		t.Fatal(err)
	}
	if err := rg1.Add(newTestRule(1)); err != nil {
		t.Fatal(err)
	}

	rg2 := NewRuleGroup()
	if err := rg2.Add(newTestRule(0)); err != nil {
		t.Fatal(err)
	}
	if err := rg2.Add(newTestRule(2)); err != nil {
		t.Fatal(err)
	}

	if err := rg1.Merge(&rg2); err != nil {
		t.Fatal(err)
	}
	// Both ID=0 rules should be added (never skipped), plus ID=2
	if rg1.Count() != 4 {
		t.Fatalf("expected 4 rules after merge (SecAction rules always added), got %d", rg1.Count())
	}
}

func TestRuleGroupMergeSkipsDuplicates(t *testing.T) {
	rg1 := NewRuleGroup()
	if err := rg1.Add(newTestRule(1)); err != nil {
		t.Fatal(err)
	}

	rg2 := NewRuleGroup()
	if err := rg2.Add(newTestRule(1)); err != nil {
		t.Fatal(err)
	}
	if err := rg2.Add(newTestRule(2)); err != nil {
		t.Fatal(err)
	}

	if err := rg1.Merge(&rg2); err != nil {
		t.Fatal(err)
	}
	// Rule ID 1 exists in both, so only rule 2 should be added
	if rg1.Count() != 2 {
		t.Fatalf("expected 2 rules (duplicate skipped), got %d", rg1.Count())
	}
}
