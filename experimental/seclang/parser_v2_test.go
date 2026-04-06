// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.experimental.crslang_parser

package seclang

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

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

func TestParser_FromFile(t *testing.T) {
	conf := `SecRuleEngine On
SecRule REQUEST_URI "@rx /admin" "id:1,phase:1,deny,status:403"
`
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.conf")
	if err := os.WriteFile(filePath, []byte(conf), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromFile(filePath); err != nil {
		t.Fatalf("FromFile() error = %v", err)
	}

	if waf.RuleEngine != types.RuleEngineOn {
		t.Errorf("RuleEngine = %v, expected On", waf.RuleEngine)
	}
	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
	if rules[0].ID_ != 1 {
		t.Errorf("Rule ID = %v, expected 1", rules[0].ID_)
	}
}

func TestParser_FromFile_Glob(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.conf", "b.conf"} {
		conf := `SecRuleEngine On` + "\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(conf), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromFile(filepath.Join(dir, "*.conf")); err != nil {
		t.Fatalf("FromFile() glob error = %v", err)
	}
	// Both files set RuleEngine On — the parse should succeed
	if waf.RuleEngine != types.RuleEngineOn {
		t.Errorf("RuleEngine = %v, expected On", waf.RuleEngine)
	}
}

func TestParser_FromFile_NotFound(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	err := parser.FromFile("/nonexistent/path/test.conf")
	if err == nil {
		t.Error("FromFile() expected error for missing file, got nil")
	}
}

func TestParser_SetRoot(t *testing.T) {
	conf := `SecRuleEngine On
SecRule REQUEST_URI "@rx /test" "id:1,phase:1,deny"
`
	memFS := fstest.MapFS{
		"rules.conf": &fstest.MapFile{Data: []byte(conf)},
	}

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
	parser.SetRoot(memFS)

	if err := parser.FromFile("rules.conf"); err != nil {
		t.Fatalf("FromFile() with SetRoot error = %v", err)
	}

	if waf.RuleEngine != types.RuleEngineOn {
		t.Errorf("RuleEngine = %v, expected On", waf.RuleEngine)
	}
	if waf.Rules.Count() != 1 {
		t.Errorf("Expected 1 rule, got %d", waf.Rules.Count())
	}
}

func TestParser_FromString_ChainRule(t *testing.T) {
	input := `SecRule REQUEST_METHOD "@rx ^POST$" "id:100,phase:1,pass,nolog,chain"
SecRule REQUEST_URI "@contains /upload" "t:none"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) != 1 {
		t.Fatalf("Expected 1 top-level rule (with chain), got %d", len(rules))
	}
	if rules[0].ID_ != 100 {
		t.Errorf("Rule ID = %v, expected 100", rules[0].ID_)
	}
	if rules[0].Chain == nil {
		t.Error("Expected chain rule to be non-nil")
	}
}

func TestParser_FromString_SecDefaultAction(t *testing.T) {
	input := `SecDefaultAction "phase:1,log,auditlog,pass"
SecRule REQUEST_URI "@rx /test" "id:200,phase:1,deny"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
	if rules[0].ID_ != 200 {
		t.Errorf("Rule ID = %v, expected 200", rules[0].ID_)
	}
}

func TestParser_FromString_SecRuleRemoveById(t *testing.T) {
	input := `SecRule REQUEST_URI "@rx /test" "id:300,phase:1,pass"
SecRuleRemoveById 300`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) != 0 {
		t.Errorf("Expected 0 rules after removal, got %d", len(rules))
	}
}

func TestParser_FromString_SecRuleRemoveByTag(t *testing.T) {
	// Note: SecRuleRemoveByTag parsing is accepted by the grammar, but the
	// crslang listener does not currently extract the tag value from the directive.
	// The converter handles this gracefully (iterates over an empty Tags slice).
	input := `SecRule REQUEST_URI "@rx /test" "id:310,phase:1,pass,tag:'removal-test'"
SecRuleRemoveByTag removal-test`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	err := parser.FromString(input)
	if err != nil {
		t.Fatalf("FromString() unexpected error = %v", err)
	}
}

func TestParser_FromString_SecRuleUpdateTargetById(t *testing.T) {
	input := `SecRule REQUEST_URI "@rx /test" "id:400,phase:1,pass"
SecRuleUpdateTargetById 400 REQUEST_METHOD`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_SecRuleUpdateTargetById_NotFound(t *testing.T) {
	// Updating a non-existent rule should log a warning and not fail
	input := `SecRuleUpdateTargetById 9999 REQUEST_METHOD`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() unexpected error = %v", err)
	}
}

func TestParser_FromString_SecRuleUpdateActionById(t *testing.T) {
	input := `SecRule REQUEST_URI "@rx /test" "id:500,phase:1,pass"
SecRuleUpdateActionById 500 "deny"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_SecRuleUpdateActionById_NotFound(t *testing.T) {
	// Updating a non-existent rule should log a warning and not fail
	input := `SecRuleUpdateActionById 9999 "deny"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() unexpected error = %v", err)
	}
}

func TestParser_FromString_RuleWithMetadata(t *testing.T) {
	input := `SecRule REQUEST_URI "@rx /admin" "id:600,phase:1,deny,msg:'Admin blocked',severity:'CRITICAL',tag:'access-control',tag:'attack/admin'"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
	rule := rules[0]
	if rule.ID_ != 600 {
		t.Errorf("Rule ID = %v, expected 600", rule.ID_)
	}
	if rule.Msg == nil {
		t.Error("Expected non-nil Msg")
	}
}

func TestParser_FromString_RuleWithTransformations(t *testing.T) {
	input := `SecRule ARGS "@rx test" "id:700,phase:2,pass,t:none,t:lowercase"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_CollectionWithSelector(t *testing.T) {
	input := `SecRule ARGS:username "@rx admin" "id:800,phase:2,deny"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_ExcludedVariable(t *testing.T) {
	input := `SecRule REQUEST_HEADERS|!REQUEST_HEADERS:User-Agent "@rx test" "id:900,phase:1,pass"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_CountVariable(t *testing.T) {
	input := `SecRule &ARGS "@eq 0" "id:1000,phase:2,pass"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_IgnoreRuleCompilationErrors(t *testing.T) {
	// A rule with an invalid regex fails during operator compilation (after ANTLR parse succeeds).
	// With IgnoreRuleCompilationErrors=true, the bad rule should be skipped silently.
	input := `SecRule REQUEST_URI "@rx (" "id:1100,phase:1,pass"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
	parser.state.IgnoreRuleCompilationErrors = true

	err := parser.FromString(input)
	if err != nil {
		t.Fatalf("FromString() with IgnoreRuleCompilationErrors error = %v", err)
	}

	// The bad rule should be skipped, so no rules should be added
	if waf.Rules.Count() != 0 {
		t.Errorf("Expected 0 rules with IgnoreRuleCompilationErrors, got %d", waf.Rules.Count())
	}
}

func TestParser_FromString_DefaultActionsPhase2(t *testing.T) {
	// Rules at phase:2 use default hardcoded actions (log,auditlog,pass)
	input := `SecRule REQUEST_URI "@rx /test" "id:1200,phase:2,pass"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
	if rules[0].Phase_ != 2 {
		t.Errorf("Rule Phase = %v, expected 2", rules[0].Phase_)
	}
}

func TestParser_FromString_MultipleDefaultActionsPhases(t *testing.T) {
	input := `SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
SecRule REQUEST_URI "@rx /test" "id:1300,phase:1,deny"
SecRule ARGS "@rx attack" "id:1301,phase:2,deny"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) != 2 {
		t.Fatalf("Expected 2 rules, got %d", len(rules))
	}
}

func TestParser_FromString_SecRuleWithVersion(t *testing.T) {
	input := `SecRule REQUEST_URI "@rx /test" "id:1400,phase:1,pass,nolog,ver:'OWASP_CRS/4.0.0'"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_SecActionWithSetvar(t *testing.T) {
	input := `SecAction "id:1500,phase:1,pass,nolog,setvar:tx.paranoia_level=1"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
	if rules[0].ID_ != 1500 {
		t.Errorf("Rule ID = %v, expected 1500", rules[0].ID_)
	}
}

func TestParser_FromString_SecActionChainToSecRule(t *testing.T) {
	// SecAction with chain action followed by SecRule
	input := `SecAction "id:1600,phase:1,pass,nolog,chain"
SecRule REQUEST_URI "@rx /test" "t:none"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) != 1 {
		t.Fatalf("Expected 1 top-level rule (with chain), got %d", len(rules))
	}
	if rules[0].ID_ != 1600 {
		t.Errorf("Rule ID = %v, expected 1600", rules[0].ID_)
	}
	if rules[0].Chain == nil {
		t.Error("Expected chain rule to be non-nil")
	}
}

func TestParser_FromString_SecRuleRemoveByIdRange(t *testing.T) {
	input := `SecRule REQUEST_URI "@rx /a" "id:1700,phase:1,pass"
SecRule REQUEST_URI "@rx /b" "id:1701,phase:1,pass"
SecRule REQUEST_URI "@rx /c" "id:1800,phase:1,pass"
SecRuleRemoveById 1700-1701`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) != 1 {
		t.Errorf("Expected 1 rule after range removal, got %d", len(rules))
	}
	if len(rules) > 0 && rules[0].ID_ != 1800 {
		t.Errorf("Remaining rule ID = %v, expected 1800", rules[0].ID_)
	}
}

func TestParser_FromString_SecRuleWithRevAndVer(t *testing.T) {
	input := `SecRule REQUEST_URI "@rx /test" "id:1900,phase:1,pass,nolog,rev:'2',ver:'OWASP_CRS/4.0.0'"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_SecRuleUpdateTargetByIdCountVar(t *testing.T) {
	input := `SecRule REQUEST_URI "@rx /test" "id:2000,phase:1,pass"
SecRuleUpdateTargetById 2000 &ARGS`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_SecRequestBodyAccessInvalid(t *testing.T) {
	input := `SecRequestBodyAccess maybe`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	err := parser.FromString(input)
	if err == nil {
		t.Error("FromString() expected error for invalid boolean, got nil")
	}
}

func TestParser_FromFile_WithSubdirectory(t *testing.T) {
	// Test FromFile resolving relative paths in subdirectories
	dir := t.TempDir()
	subDir := dir + "/sub"
	if err := os.MkdirAll(subDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	conf := `SecRuleEngine On
SecRule REQUEST_URI "@rx /test" "id:1,phase:1,deny"
`
	filePath := subDir + "/test.conf"
	if err := os.WriteFile(filePath, []byte(conf), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromFile(filePath); err != nil {
		t.Fatalf("FromFile() error = %v", err)
	}

	if waf.Rules.Count() != 1 {
		t.Errorf("Expected 1 rule, got %d", waf.Rules.Count())
	}
}

func TestParser_FromString_SecRuleUpdateActionByIdDisruptive(t *testing.T) {
	// Test SecRuleUpdateActionById replacing a disruptive action
	input := `SecRule REQUEST_URI "@rx /test" "id:2100,phase:1,pass"
SecRuleUpdateActionById 2100 "deny"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_SecRuleWithExcludedAndCountCollection(t *testing.T) {
	// Test a rule with an excluded variable in a collection (builds variable string)
	input := `SecRule REQUEST_HEADERS|!REQUEST_HEADERS:Content-Type "@rx test" "id:2200,phase:1,pass"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_SecRuleUpdateTargetByIdExcludedVar(t *testing.T) {
	// Test SecRuleUpdateTargetById adding an excluded variable
	input := `SecRule REQUEST_HEADERS "@rx test" "id:2300,phase:1,pass"
SecRuleUpdateTargetById 2300 !REQUEST_HEADERS:User-Agent`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_SecRuleNegatedOperator(t *testing.T) {
	// Test a rule with a negated operator (!@rx)
	input := `SecRule REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)" "id:2400,phase:1,pass,nolog"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_SecRuleWithAllMetadata(t *testing.T) {
	// Test a rule with all metadata fields including rev and ver
	input := `SecRule REQUEST_URI "@rx /test" "id:2500,phase:1,deny,msg:'Test',severity:'CRITICAL',tag:'test',rev:'2',ver:'OWASP_CRS/4.0.0'"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
	if rules[0].ID_ != 2500 {
		t.Errorf("Rule ID = %v, expected 2500", rules[0].ID_)
	}
}

func TestParser_FromString_SecRuleMultipleCollectionArgs(t *testing.T) {
	// Test a rule with multiple collection arguments
	input := `SecRule ARGS:foo|ARGS:bar "@rx attack" "id:2600,phase:2,deny"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_SecRuleUpdateTargetByIdBodyVar(t *testing.T) {
	// Test SecRuleUpdateTargetById with a body variable
	input := `SecRule REQUEST_URI "@rx /test" "id:2700,phase:1,pass"
SecRuleUpdateTargetById 2700 REQUEST_BODY`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_SecDefaultActionPhase2Override(t *testing.T) {
	// Test that SecDefaultAction for phase:2 overrides the hardcoded defaults
	// and exercises the mergeActions code path
	input := `SecDefaultAction "phase:2,log,auditlog,deny"
SecRule ARGS "@rx attack" "id:2800,phase:2,pass"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_SecRuleInvalidRegex(t *testing.T) {
	// Test that operator initialization errors are returned properly
	// (invalid regex that passes ANTLR but fails during compilation)
	input := `SecRule REQUEST_URI "@rx (" "id:2900,phase:1,pass"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	err := parser.FromString(input)
	if err == nil {
		t.Error("FromString() expected error for invalid regex, got nil")
	}
}

func TestParser_FromString_SecRuleWithMaturity(t *testing.T) {
	// Test a rule with the maturity metadata field
	input := `SecRule REQUEST_URI "@rx /test" "id:3000,phase:1,pass,maturity:'2'"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}
}

func TestParser_FromString_DisabledRuleAction(t *testing.T) {
	// Test that a disabled action causes an error unless IgnoreRuleCompilationErrors is set
	input := `SecRule REQUEST_URI "@rx /test" "id:3100,phase:1,deny"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
	parser.state.DisabledRuleActions = []string{"deny"}

	err := parser.FromString(input)
	if err == nil {
		t.Error("FromString() expected error for disabled action, got nil")
	}
}

func TestParser_FromString_DisabledRuleOperator(t *testing.T) {
	// Test that a disabled operator causes an error
	input := `SecRule REQUEST_URI "@rx /test" "id:3200,phase:1,pass"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
	parser.state.DisabledRuleOperators = []string{"rx"}

	err := parser.FromString(input)
	if err == nil {
		t.Error("FromString() expected error for disabled operator, got nil")
	}
}

func TestParser_FromString_SecRuleChainToSecAction(t *testing.T) {
	// Test SecRule chain → SecAction (exercises convertChainableDirective SecAction case)
	input := `SecRule REQUEST_METHOD "@rx ^POST$" "id:3300,phase:1,pass,nolog,chain"
SecAction "setvar:tx.counter=+1"`

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	if err := parser.FromString(input); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}

	rules := waf.Rules.GetRules()
	if len(rules) != 1 {
		t.Fatalf("Expected 1 top-level rule (with chain), got %d", len(rules))
	}
	if rules[0].ID_ != 3300 {
		t.Errorf("Rule ID = %v, expected 3300", rules[0].ID_)
	}
	if rules[0].Chain == nil {
		t.Error("Expected chain rule to be non-nil")
	}
}

func TestParser_FromFile_RelativePath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	conf := `SecRuleEngine On`
	if err := os.WriteFile(filepath.Join(dir, "relative.conf"), []byte(conf), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	// Use a relative path - this triggers osFS.Open's relative path branch
	if err := parser.FromFile("relative.conf"); err != nil {
		t.Fatalf("FromFile() relative path error = %v", err)
	}

	if waf.RuleEngine != types.RuleEngineOn {
		t.Errorf("RuleEngine = %v, expected On", waf.RuleEngine)
	}
}
