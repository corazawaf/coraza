//go:build coraza.rule.mandatory_rule_id_check
// +build coraza.rule.mandatory_rule_id_check

package corazawaf

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
)

func TestRuleIDMandatoryCondition(t *testing.T) {
	r := NewRule()
	r.Msg, _ = macro.NewMacro("test-rule")
	r.Tags_ = []string{
		"test/no-id",
	}

	rg := NewRuleGroup()
	if err := rg.Add(r); err == nil {
		t.Error("Expected error - rule without id should not be allowed")
	}
}

func TestRuleIDDuplicate(t *testing.T) {
	r := newTestRule(1)

	rg := NewRuleGroup()
	if err := rg.Add(r); err != nil {
		t.Error("Failed to add rule to rulegroup")
	}

	if rg.Count() != 1 {
		t.Error("Failed to add rule to rulegroup")
	}

	sr := newTestRule(1)
	if err := rg.Add(sr); err == nil {
		t.Error("Expected error - duplicate rule id should not be allowed")
	}
}
