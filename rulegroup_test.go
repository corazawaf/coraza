// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"testing"
)

func TestRG(t *testing.T) {
	r := NewRule()
	macroMsg, _ := NewMacro("test")
	r.Msg = *macroMsg
	r.ID = 1
	r.Tags = []string{
		"test",
	}

	rg := NewRuleGroup()
	if err := rg.Add(r); err != nil {
		t.Error("Failed to add rule to rulegroup")
	}

	if rg.Count() != 1 {
		t.Error("Failed to add rule to rulegroup")
	}

	if len(rg.FindByMsg("test")) != 1 {
		t.Error("Failed to find rules by msg")
	}

	if len(rg.FindByTag("test")) != 1 {
		t.Error("Failed to find rules by tag")
	}

	rg.DeleteByID(1)
	if rg.Count() != 0 {
		t.Error("Failed to remove rule from rulegroup")
	}
}
