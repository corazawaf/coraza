// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"slices"
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

// Not a profile: engine profiles compile directives into one WAF and cannot add a shared *Rule to two RuleGroups.
func TestRuleGroupAddIsolatesMutableState(t *testing.T) {
	noopTransform := func(v string) (string, bool, error) { return v, false, nil }
	buildSharedRule := func(t *testing.T) *Rule {
		t.Helper()
		r := NewRule()
		r.ID_ = 42
		r.LogID_ = "42"
		r.Phase_ = types.PhaseRequestHeaders
		r.Tags_ = make([]string, 1, 4)
		r.Tags_[0] = "base-tag"

		r.variables = make([]ruleVariableParams, 0, 4)
		if err := r.AddVariable(variables.ArgsGet, "k", false); err != nil {
			t.Fatal(err)
		}
		r.variables[0].Exceptions = make([]ruleVariableException, 1, 4)
		r.variables[0].Exceptions[0] = ruleVariableException{KeyStr: "base-exc"}

		r.SetOperator(&dummyEqOperator{}, "@eq", "0")

		r.transformations = make([]ruleTransformationParams, 0, 4)
		r.transformationPrefixIDs = make([]int, 0, 4)
		if err := r.AddTransformation("t1", noopTransform); err != nil {
			t.Fatal(err)
		}

		r.actions = make([]ruleActionParams, 0, 4)
		if err := r.AddAction("deny", &dummyDenyAction{}); err != nil {
			t.Fatal(err)
		}

		child := NewRule()
		child.ParentID_ = 42
		child.LogID_ = "42"
		child.Phase_ = 0
		child.Tags_ = make([]string, 1, 4)
		child.Tags_[0] = "child-base"
		child.variables = make([]ruleVariableParams, 0, 4)
		if err := child.AddVariable(variables.RequestHeaders, "h", false); err != nil {
			t.Fatal(err)
		}
		child.variables[0].Exceptions = make([]ruleVariableException, 1, 4)
		child.variables[0].Exceptions[0] = ruleVariableException{KeyStr: "child-exc"}
		child.SetOperator(&dummyEqOperator{}, "@eq", "0")
		child.transformations = make([]ruleTransformationParams, 0, 4)
		child.transformationPrefixIDs = make([]int, 0, 4)
		if err := child.AddTransformation("ct1", noopTransform); err != nil {
			t.Fatal(err)
		}
		child.actions = make([]ruleActionParams, 0, 4)
		if err := child.AddAction("nolog", &dummyNonDisruptiveAction{}); err != nil {
			t.Fatal(err)
		}

		r.HasChain = true
		r.Chain = child
		return r
	}

	tests := []struct {
		name   string
		mutate func(t *testing.T, src, g1, g2 *Rule)
		assert func(t *testing.T, src, g1, g2 *Rule)
	}{
		{
			name: "tags with spare capacity",
			mutate: func(_ *testing.T, src, g1, g2 *Rule) {
				g1.Tags_ = append(g1.Tags_, "g1-tag")
				g2.Tags_ = append(g2.Tags_, "g2-tag")
				src.Tags_ = append(src.Tags_, "src-tag")
			},
			assert: func(t *testing.T, src, g1, g2 *Rule) {
				if !slices.Equal(g1.Tags_, []string{"base-tag", "g1-tag"}) {
					t.Errorf("group 1 tags = %v, want [base-tag g1-tag]", g1.Tags_)
				}
				if !slices.Equal(g2.Tags_, []string{"base-tag", "g2-tag"}) {
					t.Errorf("group 2 tags = %v, want [base-tag g2-tag]", g2.Tags_)
				}
				if !slices.Equal(src.Tags_, []string{"base-tag", "src-tag"}) {
					t.Errorf("source rule tags = %v, want [base-tag src-tag]", src.Tags_)
				}
			},
		},
		{
			name: "variables and exceptions with spare capacity",
			mutate: func(t *testing.T, src, g1, g2 *Rule) {
				if err := g1.AddVariable(variables.RequestURI, "", false); err != nil {
					t.Fatal(err)
				}
				if err := g2.AddVariable(variables.QueryString, "", false); err != nil {
					t.Fatal(err)
				}
				if err := g1.AddVariableNegation(variables.ArgsGet, "g1-exc"); err != nil {
					t.Fatal(err)
				}
				if err := g2.AddVariableNegation(variables.ArgsGet, "g2-exc"); err != nil {
					t.Fatal(err)
				}
				if err := src.AddVariableNegation(variables.ArgsGet, "src-exc"); err != nil {
					t.Fatal(err)
				}
			},
			assert: func(t *testing.T, src, g1, g2 *Rule) {
				if g1.variables[len(g1.variables)-1].Variable != variables.RequestURI {
					t.Errorf("group 1 last variable = %v, want REQUEST_URI", g1.variables[len(g1.variables)-1].Variable)
				}
				if g2.variables[len(g2.variables)-1].Variable != variables.QueryString {
					t.Errorf("group 2 last variable = %v, want QUERY_STRING", g2.variables[len(g2.variables)-1].Variable)
				}
				if len(src.variables) != 1 {
					t.Errorf("source variables len = %d, want 1", len(src.variables))
				}
				if got := g1.variables[0].Exceptions; len(got) != 2 || got[1].KeyStr != "g1-exc" {
					t.Errorf("group 1 exceptions = %+v, want [base-exc g1-exc]", got)
				}
				if got := g2.variables[0].Exceptions; len(got) != 2 || got[1].KeyStr != "g2-exc" {
					t.Errorf("group 2 exceptions = %+v, want [base-exc g2-exc]", got)
				}
				if got := src.variables[0].Exceptions; len(got) != 2 || got[1].KeyStr != "src-exc" {
					t.Errorf("source exceptions = %+v, want [base-exc src-exc]", got)
				}
			},
		},
		{
			name: "operator descriptor",
			mutate: func(_ *testing.T, _, g1, g2 *Rule) {
				g1.operator.Data = "1"
				g2.operator.Negation = true
			},
			assert: func(t *testing.T, src, g1, g2 *Rule) {
				if g1.operator.Data != "1" || g1.operator.Negation {
					t.Errorf("group 1 operator = %+v, want Data=1 Negation=false", g1.operator)
				}
				if g2.operator.Data != "0" || !g2.operator.Negation {
					t.Errorf("group 2 operator = %+v, want Data=0 Negation=true", g2.operator)
				}
				if src.operator.Data != "0" || src.operator.Negation {
					t.Errorf("source operator = %+v, want Data=0 Negation=false", src.operator)
				}
			},
		},
		{
			name: "transformations and prefix IDs with spare capacity",
			mutate: func(t *testing.T, _, g1, g2 *Rule) {
				if err := g1.AddTransformation("g1-trans", noopTransform); err != nil {
					t.Fatal(err)
				}
				if err := g2.AddTransformation("g2-trans", noopTransform); err != nil {
					t.Fatal(err)
				}
			},
			assert: func(t *testing.T, src, g1, g2 *Rule) {
				if len(g1.transformations) != 2 || len(g2.transformations) != 2 || len(src.transformations) != 1 {
					t.Fatalf("unexpected transformation lengths: g1=%d g2=%d src=%d", len(g1.transformations), len(g2.transformations), len(src.transformations))
				}
				if g1.transformationPrefixIDs[1] == g2.transformationPrefixIDs[1] {
					t.Errorf("group 1 and group 2 share transformationPrefixIDs[1] = %d", g1.transformationPrefixIDs[1])
				}
			},
		},
		{
			name: "actions with spare capacity",
			mutate: func(t *testing.T, _, g1, g2 *Rule) {
				if err := g1.AddAction("g1-act", &dummyNonDisruptiveAction{}); err != nil {
					t.Fatal(err)
				}
				if err := g2.AddAction("g2-act", &dummyNonDisruptiveAction{}); err != nil {
					t.Fatal(err)
				}
				g2.ClearDisruptiveActions()
			},
			assert: func(t *testing.T, src, g1, g2 *Rule) {
				if len(g1.actions) != 2 || g1.actions[0].Name != "deny" || g1.actions[1].Name != "g1-act" {
					t.Errorf("group 1 actions = %+v, want [deny g1-act]", g1.actions)
				}
				if len(g2.actions) != 1 || g2.actions[0].Name != "g2-act" {
					t.Errorf("group 2 actions = %+v, want [g2-act]", g2.actions)
				}
				if len(src.actions) != 1 || src.actions[0].Name != "deny" {
					t.Errorf("source actions = %+v, want [deny]", src.actions)
				}
			},
		},
		{
			name: "chained rule links",
			mutate: func(t *testing.T, src, g1, g2 *Rule) {
				g1.Chain.Tags_ = append(g1.Chain.Tags_, "g1-child")
				g2.Chain.Tags_ = append(g2.Chain.Tags_, "g2-child")
				if err := g1.Chain.AddVariableNegation(variables.RequestHeaders, "g1-hdr"); err != nil {
					t.Fatal(err)
				}
				if err := g2.Chain.AddVariableNegation(variables.RequestHeaders, "g2-hdr"); err != nil {
					t.Fatal(err)
				}
				g2.Chain.operator.Negation = true
				g2.Chain.ClearTransformations()
				if err := g2.Chain.AddAction("g2-child-act", &dummyNonDisruptiveAction{}); err != nil {
					t.Fatal(err)
				}
				g2.Chain.Chain = NewRule()
				src.Chain.Tags_ = append(src.Chain.Tags_, "src-child")
			},
			assert: func(t *testing.T, src, g1, g2 *Rule) {
				if !slices.Equal(g1.Chain.Tags_, []string{"child-base", "g1-child"}) {
					t.Errorf("group 1 chain tags = %v, want [child-base g1-child]", g1.Chain.Tags_)
				}
				if !slices.Equal(g2.Chain.Tags_, []string{"child-base", "g2-child"}) {
					t.Errorf("group 2 chain tags = %v, want [child-base g2-child]", g2.Chain.Tags_)
				}
				if !slices.Equal(src.Chain.Tags_, []string{"child-base", "src-child"}) {
					t.Errorf("source chain tags = %v, want [child-base src-child]", src.Chain.Tags_)
				}
				if got := g1.Chain.variables[0].Exceptions; len(got) != 2 || got[1].KeyStr != "g1-hdr" {
					t.Errorf("group 1 chain exceptions = %+v, want [child-exc g1-hdr]", got)
				}
				if got := g2.Chain.variables[0].Exceptions; len(got) != 2 || got[1].KeyStr != "g2-hdr" {
					t.Errorf("group 2 chain exceptions = %+v, want [child-exc g2-hdr]", got)
				}
				if g1.Chain.operator.Negation || len(g1.Chain.transformations) != 1 || len(g1.Chain.actions) != 1 {
					t.Errorf("group 2 chain mutations leaked into group 1 chain: op=%+v trans=%d actions=%d", g1.Chain.operator, len(g1.Chain.transformations), len(g1.Chain.actions))
				}
				if g1.Chain.Chain != nil || src.Chain.Chain != nil {
					t.Error("attaching a link in group 2 leaked to group 1 or source")
				}
				if g1.chainMinPhase != types.PhaseRequestHeaders || src.chainMinPhase != types.PhaseUnknown {
					t.Errorf("chainMinPhase: g1=%v src=%v, want %v and %v", g1.chainMinPhase, src.chainMinPhase, types.PhaseRequestHeaders, types.PhaseUnknown)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := buildSharedRule(t)
			rg1 := NewRuleGroup()
			var observed types.RuleMetadata
			rg1.SetObserver(func(r types.RuleMetadata) {
				observed = r
			})
			rg2 := NewRuleGroup()
			if err := rg1.Add(src); err != nil {
				t.Fatalf("rg1.Add failed: %v", err)
			}
			if err := rg2.Add(src); err != nil {
				t.Fatalf("rg2.Add failed: %v", err)
			}

			g1 := rg1.FindByID(42)
			g2 := rg2.FindByID(42)
			tt.mutate(t, src, g1, g2)
			tt.assert(t, src, g1, g2)
			if !slices.Equal(observed.Tags(), []string{"base-tag"}) {
				t.Errorf("observer tags = %v, want [base-tag]", observed.Tags())
			}
		})
	}
}
