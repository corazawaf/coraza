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
	r.Msg, _ = macro.NewMacro("test-Msg")
	r.Tags_ = []string{
		"Test-Tag",
	}
	return r
}

func TestRuleGroupDeleteByTag(t *testing.T) {
	t.Run("matches exact case", func(t *testing.T) {
		rg := NewRuleGroup()
		if err := rg.Add(newTestRule(1)); err != nil {
			t.Fatal("Failed to add rule to rulegroup")
		}
		rg.DeleteByTag("Test-Tag")
		if rg.Count() != 0 {
			t.Error("Expected rule to be removed")
		}
	})

	t.Run("does not match different case", func(t *testing.T) {
		rg := NewRuleGroup()
		if err := rg.Add(newTestRule(1)); err != nil {
			t.Fatal("Failed to add rule to rulegroup")
		}
		rg.DeleteByTag("TEST-TAG")
		if rg.Count() != 1 {
			t.Error("Expected rule to remain when tag case does not match")
		}
	})
}

func TestRuleGroupDeleteByMsg(t *testing.T) {
	t.Run("matches exact case", func(t *testing.T) {
		rg := NewRuleGroup()
		if err := rg.Add(newTestRule(1)); err != nil {
			t.Fatal("Failed to add rule to rulegroup")
		}
		rg.DeleteByMsg("test-Msg")
		if rg.Count() != 0 {
			t.Error("Expected rule to be removed")
		}
	})

	t.Run("does not match different case", func(t *testing.T) {
		rg := NewRuleGroup()
		if err := rg.Add(newTestRule(1)); err != nil {
			t.Fatal("Failed to add rule to rulegroup")
		}
		rg.DeleteByMsg("TEST-MSG")
		if rg.Count() != 1 {
			t.Error("Expected rule to remain when message case does not match")
		}
	})
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
