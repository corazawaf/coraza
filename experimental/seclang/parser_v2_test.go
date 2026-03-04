// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

func TestParser_FromString_RuleEngine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected types.RuleEngineStatus
	}{
		{
			name:     "SecRuleEngine On",
			input:    "SecRuleEngine On",
			expected: types.RuleEngineOn,
		},
		{
			name:     "SecRuleEngine Off",
			input:    "SecRuleEngine Off",
			expected: types.RuleEngineOff,
		},
		{
			name:     "SecRuleEngine DetectionOnly",
			input:    "SecRuleEngine DetectionOnly",
			expected: types.RuleEngineDetectionOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := corazawaf.NewWAF()
			parser := NewParser(waf)

			err := parser.FromString(tt.input)
			if err != nil {
				t.Fatalf("FromString() error = %v", err)
			}

			if waf.RuleEngine != tt.expected {
				t.Errorf("RuleEngine = %v, expected %v", waf.RuleEngine, tt.expected)
			}
		})
	}
}

func TestParser_FromString_RequestBodyAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "SecRequestBodyAccess On",
			input:    "SecRequestBodyAccess On",
			expected: true,
		},
		{
			name:     "SecRequestBodyAccess Off",
			input:    "SecRequestBodyAccess Off",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := corazawaf.NewWAF()
			parser := NewParser(waf)

			err := parser.FromString(tt.input)
			if err != nil {
				t.Fatalf("FromString() error = %v", err)
			}

			if waf.RequestBodyAccess != tt.expected {
				t.Errorf("RequestBodyAccess = %v, expected %v", waf.RequestBodyAccess, tt.expected)
			}
		})
	}
}

func TestParser_FromString_ResponseBodyAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "SecResponseBodyAccess On",
			input:    "SecResponseBodyAccess On",
			expected: true,
		},
		{
			name:     "SecResponseBodyAccess Off",
			input:    "SecResponseBodyAccess Off",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := corazawaf.NewWAF()
			parser := NewParser(waf)

			err := parser.FromString(tt.input)
			if err != nil {
				t.Fatalf("FromString() error = %v", err)
			}

			if waf.ResponseBodyAccess != tt.expected {
				t.Errorf("ResponseBodyAccess = %v, expected %v", waf.ResponseBodyAccess, tt.expected)
			}
		})
	}
}

func TestParser_FromString_BodyLimits(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		checkReq bool
		checkRes bool
		expected int64
	}{
		{
			name:     "SecRequestBodyLimit",
			input:    "SecRequestBodyLimit 131072",
			checkReq: true,
			expected: 131072,
		},
		{
			name:     "SecResponseBodyLimit",
			input:    "SecResponseBodyLimit 524288",
			checkRes: true,
			expected: 524288,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := corazawaf.NewWAF()
			parser := NewParser(waf)

			err := parser.FromString(tt.input)
			if err != nil {
				t.Fatalf("FromString() error = %v", err)
			}

			if tt.checkReq && waf.RequestBodyLimit != tt.expected {
				t.Errorf("RequestBodyLimit = %v, expected %v", waf.RequestBodyLimit, tt.expected)
			}
			if tt.checkRes && waf.ResponseBodyLimit != tt.expected {
				t.Errorf("ResponseBodyLimit = %v, expected %v", waf.ResponseBodyLimit, tt.expected)
			}
		})
	}
}

func TestParser_FromString_MultipleDirectives(t *testing.T) {
	input := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRequestBodyLimit 131072
		SecResponseBodyAccess Off
	`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	err := parser.FromString(input)
	if err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	if waf.RuleEngine != types.RuleEngineOn {
		t.Errorf("RuleEngine = %v, expected On", waf.RuleEngine)
	}
	if !waf.RequestBodyAccess {
		t.Error("RequestBodyAccess should be true")
	}
	if waf.RequestBodyLimit != 131072 {
		t.Errorf("RequestBodyLimit = %v, expected 131072", waf.RequestBodyLimit)
	}
	if waf.ResponseBodyAccess {
		t.Error("ResponseBodyAccess should be false")
	}
}

func TestParser_FromString_Comments(t *testing.T) {
	input := `
		# This is a comment
		SecRuleEngine On
		# Another comment
		SecRequestBodyAccess On
	`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	err := parser.FromString(input)
	if err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	if waf.RuleEngine != types.RuleEngineOn {
		t.Errorf("RuleEngine = %v, expected On", waf.RuleEngine)
	}
}

func TestParser_FromString_SecRule(t *testing.T) {
	input := `SecRule REQUEST_URI "@rx /admin" "id:1,phase:1,deny,status:403,msg:'Admin access denied'"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	err := parser.FromString(input)
	if err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}

	rule := rules[0]
	if rule.ID_ != 1 {
		t.Errorf("Rule ID = %v, expected 1", rule.ID_)
	}
	if rule.Phase_ != 1 {
		t.Errorf("Rule Phase = %v, expected 1", rule.Phase_)
	}
}

func TestParser_FromString_SecAction(t *testing.T) {
	input := `SecAction "id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=1"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	err := parser.FromString(input)
	if err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}

	rule := rules[0]
	if rule.ID_ != 900000 {
		t.Errorf("Rule ID = %v, expected 900000", rule.ID_)
	}
	if rule.Phase_ != 1 {
		t.Errorf("Rule Phase = %v, expected 1", rule.Phase_)
	}
}

func TestParser_FromString_SecMarker(t *testing.T) {
	// SecMarker in ANTLR grammar is stored as a DirectiveList Marker,
	// not as a rule. It acts as a section boundary.
	input := `SecMarker "END_HOST_CHECK"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	err := parser.FromString(input)
	if err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}

	rule := rules[0]
	if rule.SecMark_ != "END_HOST_CHECK" {
		t.Errorf("SecMark = %q, expected END_HOST_CHECK", rule.SecMark_)
	}
}

func TestParser_FromString_SecComponentSignature(t *testing.T) {
	input := `SecComponentSignature "OWASP_CRS/4.0.0"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	err := parser.FromString(input)
	if err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	if len(waf.ComponentNames) == 0 {
		t.Fatal("Expected at least one component name")
	}
	// The value may include quotes depending on how the parser handles it
	found := false
	for _, name := range waf.ComponentNames {
		if name == "OWASP_CRS/4.0.0" || name == `"OWASP_CRS/4.0.0"` {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ComponentNames = %v, expected to contain OWASP_CRS/4.0.0", waf.ComponentNames)
	}
}

func TestParser_SyntaxErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Invalid directive",
			input: "InvalidDirective blah",
		},
		{
			name:  "Malformed input",
			input: "SecRuleEngine",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := corazawaf.NewWAF()
			parser := NewParser(waf)

			err := parser.FromString(tt.input)
			if err == nil {
				t.Error("FromString() expected error, got nil")
			}
		})
	}
}

func TestParser_FromString_MultipleRules(t *testing.T) {
	input := `
		SecRuleEngine On
		SecRule REQUEST_METHOD "@rx ^POST$" "id:1,phase:1,pass,nolog"
		SecRule REQUEST_URI "@contains /admin" "id:2,phase:1,deny,status:403"
	`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	err := parser.FromString(input)
	if err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) != 2 {
		t.Fatalf("Expected 2 rules, got %d", len(rules))
	}

	if rules[0].ID_ != 1 {
		t.Errorf("First rule ID = %v, expected 1", rules[0].ID_)
	}
	if rules[1].ID_ != 2 {
		t.Errorf("Second rule ID = %v, expected 2", rules[1].ID_)
	}
}
