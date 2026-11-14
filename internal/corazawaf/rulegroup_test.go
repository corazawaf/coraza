// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
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

	t.Run("keeps rules without msg", func(t *testing.T) {
		rg := NewRuleGroup()
		r1 := newTestRule(1)
		r2 := NewRule()
		r2.ID_ = 2
		if err := rg.Add(r1); err != nil {
			t.Fatal("Failed to add rule to rulegroup")
		}
		if err := rg.Add(r2); err != nil {
			t.Fatal("Failed to add rule to rulegroup")
		}
		rg.DeleteByMsg("test-Msg")
		if rg.Count() != 1 {
			t.Error("Expected only the rule without msg to remain")
		}
		if rg.GetRules()[0].ID_ != 2 {
			t.Error("Expected the rule without msg to be kept")
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

func TestRuleGroupEvalEmptiesTransformationCache(t *testing.T) {
	// Below the threshold the map is emptied in place, above it is replaced:
	// either way no entry must outlive the phase.
	for _, n := range []int{2, maxRetainedTransformationCacheEntries + 1} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			r := newTestRule(1)
			r.Phase_ = types.PhaseRequestHeaders
			if err := r.AddVariable(variables.ArgsGet, "", false); err != nil {
				t.Fatal(err)
			}
			if err := r.AddTransformation("lowercase", func(input string) (string, bool, error) {
				return strings.ToLower(input), true, nil
			}); err != nil {
				t.Fatal(err)
			}
			r.SetOperator(&dummyEqOperator{}, "@eq", "0")

			waf := NewWAF()
			waf.ArgumentLimit = n
			if err := waf.Rules.Add(r); err != nil {
				t.Fatal(err)
			}
			tx := waf.NewTransaction()
			defer tx.Close()
			for i := 0; i < n; i++ {
				tx.AddGetRequestArgument("arg"+strconv.Itoa(i), "Value"+strconv.Itoa(i))
			}
			tx.ProcessRequestHeaders()

			if got := tx.variables.argsGet.Len(); got != n {
				t.Fatalf("got %d arguments, want %d", got, n)
			}
			if got := len(tx.transformationCache); got != 0 {
				t.Errorf("transformation cache holds %d entries after the phase, want 0", got)
			}
		})
	}
}
