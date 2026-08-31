// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

// The update directives took the address of a range variable over
// GetRules(), which returns []Rule by value, so every target they added was
// written to a copy and discarded. The directive still parsed and returned
// no error, so it failed silently. See corazawaf/coraza#1700.
//
// These assert the effective target set by exercising it: the base rule only
// inspects ARGS, so a payload in a header matches only once REQUEST_HEADERS
// has genuinely been added.
func TestUpdateTargetAppliesToStoredRule(t *testing.T) {
	const base = `SecRule ARGS "@rx attackpayload" "id:5,phase:2,pass,log,tag:mytag"`

	tests := []struct {
		name      string
		directive string
	}{
		{"by single id", `SecRuleUpdateTargetById 5 "REQUEST_HEADERS"`},
		{"by id range", `SecRuleUpdateTargetById 1-10 "REQUEST_HEADERS"`},
		{"by tag", `SecRuleUpdateTargetByTag "mytag" "REQUEST_HEADERS"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !headerPayloadMatches(t, base+"\n"+tc.directive) {
				t.Errorf("%s did not add the target to the stored rule", tc.directive)
			}
		})
	}

	t.Run("no update leaves the rule alone", func(t *testing.T) {
		if headerPayloadMatches(t, base) {
			t.Error("rule scoped to ARGS must not match a header payload")
		}
	})
}

// headerPayloadMatches reports whether rule 5 fires on a payload carried in a
// request header.
func headerPayloadMatches(t *testing.T, directives string) bool {
	t.Helper()
	waf := corazawaf.NewWAF()
	waf.RuleEngine = types.RuleEngineDetectionOnly
	p := NewParser(waf)
	if err := p.FromString(directives); err != nil {
		t.Fatalf("parsing directives: %v", err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessURI("/x", "GET", "HTTP/1.1")
	tx.AddRequestHeader("X-Probe", "attackpayload")
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("processing body: %v", err)
	}
	for _, mr := range tx.MatchedRules() {
		if mr.Rule().ID() == 5 {
			return true
		}
	}
	return false
}
