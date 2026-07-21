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

func TestRuleGroupAddDuplicateID(t *testing.T) {
	rg := NewRuleGroup()
	if err := rg.Add(newTestRule(1)); err != nil {
		t.Fatalf("Failed to add rule to rulegroup: %s", err.Error())
	}
	if err := rg.Add(newTestRule(1)); err == nil {
		t.Fatal("Expected error adding a rule with a duplicated id")
	}
	if rg.Count() != 1 {
		t.Fatal("Unexpected rules in the rulegroup")
	}
}

// assertFindByID checks that FindByID resolves each present id to the right
// rule and returns nil for each absent id.
func assertFindByID(t *testing.T, rg *RuleGroup, present, absent []int) {
	t.Helper()
	for _, id := range present {
		r := rg.FindByID(id)
		if r == nil {
			t.Errorf("FindByID(%d): expected rule, got nil", id)
		} else if r.ID_ != id {
			t.Errorf("FindByID(%d): got rule with id %d", id, r.ID_)
		}
	}
	for _, id := range absent {
		if r := rg.FindByID(id); r != nil {
			t.Errorf("FindByID(%d): expected nil, got rule with id %d", id, r.ID_)
		}
	}
}

func newTestRuleGroup(t *testing.T, ids ...int) RuleGroup {
	t.Helper()
	rg := NewRuleGroup()
	for _, id := range ids {
		if err := rg.Add(newTestRule(id)); err != nil {
			t.Fatalf("Failed to add rule to rulegroup: %s", err.Error())
		}
	}
	return rg
}

func TestRuleGroupFindByIDAfterDelete(t *testing.T) {
	t.Run("DeleteByID front", func(t *testing.T) {
		rg := newTestRuleGroup(t, 1, 2, 3, 4, 5)
		rg.DeleteByID(1)
		assertFindByID(t, &rg, []int{2, 3, 4, 5}, []int{1})
	})

	t.Run("DeleteByID middle", func(t *testing.T) {
		rg := newTestRuleGroup(t, 1, 2, 3, 4, 5)
		rg.DeleteByID(3)
		assertFindByID(t, &rg, []int{1, 2, 4, 5}, []int{3})
	})

	t.Run("DeleteByID back", func(t *testing.T) {
		rg := newTestRuleGroup(t, 1, 2, 3, 4, 5)
		rg.DeleteByID(5)
		assertFindByID(t, &rg, []int{1, 2, 3, 4}, []int{5})
	})

	t.Run("DeleteByID missing id", func(t *testing.T) {
		rg := newTestRuleGroup(t, 1, 2, 3)
		rg.DeleteByID(42)
		assertFindByID(t, &rg, []int{1, 2, 3}, []int{42})
	})

	t.Run("DeleteByRange", func(t *testing.T) {
		rg := newTestRuleGroup(t, 1, 2, 3, 4, 5)
		rg.DeleteByRange(2, 4)
		assertFindByID(t, &rg, []int{1, 5}, []int{2, 3, 4})
	})

	t.Run("DeleteByMsg", func(t *testing.T) {
		rg := newTestRuleGroup(t, 1, 2, 3)
		other := newTestRule(4)
		other.Msg, _ = macro.NewMacro("other-Msg")
		if err := rg.Add(other); err != nil {
			t.Fatalf("Failed to add rule to rulegroup: %s", err.Error())
		}
		rg.DeleteByMsg("test-Msg")
		assertFindByID(t, &rg, []int{4}, []int{1, 2, 3})
	})

	t.Run("DeleteByTag", func(t *testing.T) {
		rg := newTestRuleGroup(t, 1, 2, 3)
		other := newTestRule(4)
		other.Tags_ = []string{"Other-Tag"}
		if err := rg.Add(other); err != nil {
			t.Fatalf("Failed to add rule to rulegroup: %s", err.Error())
		}
		rg.DeleteByTag("Test-Tag")
		assertFindByID(t, &rg, []int{4}, []int{1, 2, 3})
	})
}

func TestRuleGroupDiscardPendingChain(t *testing.T) {
	t.Run("last rule without chain is kept", func(t *testing.T) {
		rg := newTestRuleGroup(t, 1, 2)
		rg.DiscardPendingChain()
		if rg.Count() != 2 {
			t.Fatal("Unexpected rules in the rulegroup")
		}
		assertFindByID(t, &rg, []int{1, 2}, nil)
	})

	t.Run("pending chain is dropped and its id reusable", func(t *testing.T) {
		rg := newTestRuleGroup(t, 1)
		chained := newTestRule(2)
		chained.HasChain = true
		if err := rg.Add(chained); err != nil {
			t.Fatalf("Failed to add rule to rulegroup: %s", err.Error())
		}
		rg.DiscardPendingChain()
		if rg.Count() != 1 {
			t.Fatal("Unexpected rules in the rulegroup")
		}
		assertFindByID(t, &rg, []int{1}, []int{2})

		// re-adding the discarded id must not report a duplicate
		if err := rg.Add(newTestRule(2)); err != nil {
			t.Fatalf("Failed to re-add rule after discard: %s", err.Error())
		}
		assertFindByID(t, &rg, []int{1, 2}, nil)
	})
}
