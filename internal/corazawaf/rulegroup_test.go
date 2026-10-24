// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"context"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/variables"
	"github.com/corazawaf/coraza/v3/types"
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

// cancellingOperator counts its evaluations, cancels the transaction's
// context at the given one and never matches.
type cancellingOperator struct {
	evaluated *int
	cancelAt  int
	cancel    context.CancelFunc
}

func (o cancellingOperator) Evaluate(plugintypes.TransactionState, string) bool {
	*o.evaluated++
	if *o.evaluated == o.cancelAt {
		o.cancel()
	}
	return false
}

// TestRuleGroupEvalStopsWhenTheContextIsDone is a test function rather than an
// engine profile because profiles cannot cancel a transaction's context.
func TestRuleGroupEvalStopsWhenTheContextIsDone(t *testing.T) {
	tests := []struct {
		name     string
		phase    types.RulePhase
		cancelAt int
		want     int
	}{
		{name: "a live context evaluates every rule", phase: types.PhaseRequestHeaders, cancelAt: 0, want: 3},
		{name: "a context done mid-phase stops the rules after it", phase: types.PhaseRequestHeaders, cancelAt: 1, want: 1},
		{name: "the logging phase runs with the context done", phase: types.PhaseLogging, cancelAt: 1, want: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			evaluated := 0
			waf := NewWAF()
			for id := 1; id <= 3; id++ {
				r := NewRule()
				r.ID_ = id
				r.Phase_ = tt.phase
				if err := r.AddVariable(variables.RequestURI, "", false); err != nil {
					t.Fatal(err)
				}
				r.SetOperator(cancellingOperator{evaluated: &evaluated, cancelAt: tt.cancelAt, cancel: cancel}, "@cancelling", "")
				if err := waf.Rules.Add(r); err != nil {
					t.Fatal(err)
				}
			}
			tx := waf.NewTransactionWithOptions(Options{ID: "ctx", Context: ctx})
			defer tx.Close()
			tx.ProcessURI("/", "GET", "HTTP/1.1")
			waf.Rules.Eval(tt.phase, tx)
			if evaluated != tt.want {
				t.Errorf("evaluated %d rules, want %d", evaluated, tt.want)
			}
		})
	}
}
