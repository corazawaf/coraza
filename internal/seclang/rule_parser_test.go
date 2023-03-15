// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"errors"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestInvalidRule(t *testing.T) {
	waf := corazawaf.NewWAF()
	p := NewParser(waf)

	err := p.FromString("")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	err = p.FromString("SecRule ")
	if err == nil {
		t.Error("expected malformed rule error")
	}
}

func TestVariables(t *testing.T) {
	waf := corazawaf.NewWAF()
	p := NewParser(waf)

	// single variable with key
	err := p.FromString(`SecRule REQUEST_HEADERS:test "" "id:1"`)
	if err != nil {
		t.Error(err)
	}
	err = p.FromString(`SecRule &REQUEST_COOKIES_NAMES:'/^(?:phpMyAdminphp|MyAdmin_https)$/' "id:2"`)
	if err != nil {
		t.Error(err)
	}
	err = p.FromString(`SecRule &REQUEST_COOKIES_NAMES:'/^(?:phpMyAdminphp|MyAdmin_https)$/'|ARGS:test "id:3"`)
	if err != nil {
		t.Error(err)
	}
	err = p.FromString(`SecRule &REQUEST_COOKIES_NAMES:'/.*/'|ARGS:/a|b/ "id:4"`)
	if err != nil {
		t.Error(err)
	}

	err = p.FromString(`SecRule &REQUEST_COOKIES_NAMES:'/.*/'|ARGS:/a|b/|XML:/*|ARGS|REQUEST_HEADERS "id:5"`)
	if err != nil {
		t.Error(err)
	}

	err = p.FromString(`SecRule XML:/*|XML://@* "" "id:6"`)
	if err != nil {
		t.Error(err)
	}
}

func TestVariableCases(t *testing.T) {
	waf := corazawaf.NewWAF()
	p := NewParser(waf)
	err := p.FromString(`SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "" "id:7,pass"`)
	if err != nil {
		t.Error(err)
	}
}

func TestSecRuleInlineVariableNegation(t *testing.T) {
	waf := corazawaf.NewWAF()
	p := NewParser(waf)
	err := p.FromString(`
		SecRule REQUEST_URI|!REQUEST_COOKIES "abc" "id:7,phase:2"
	`)
	if err != nil {
		t.Error(err)
	}

	err = p.FromString(`
		SecRule REQUEST_URI|!REQUEST_COOKIES:xyz "abc" "id:8,phase:2"
	`)
	if err != nil {
		t.Error(err)
	}

	err = p.FromString(`
		SecRule REQUEST_URI|!REQUEST_COOKIES: "abc" "id:9,phase:2"
	`)
	expectedErr := "failed to compile the directive"
	if !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("unexpected error, want %q, got %q", expectedErr, err.Error())
	}
}

func TestSecRuleUpdateTargetVariableNegation(t *testing.T) {
	waf := corazawaf.NewWAF()
	p := NewParser(waf)
	err := p.FromString(`
		SecRule REQUEST_URI|REQUEST_COOKIES "abc" "id:7,phase:2"
		SecRuleUpdateTargetById 7 "!REQUEST_HEADERS:/xyz/"
		SecRuleUpdateTargetById 7 "!REQUEST_COOKIES:/xyz/"
	`)
	if err != nil {
		t.Error(err)
	}

	err = p.FromString(`
		SecRule REQUEST_URI|REQUEST_COOKIES "abc" "id:8,phase:2"
		SecRuleUpdateTargetById 8 "!REQUEST_HEADERS:"
	`)
	expectedErr := errors.New("unknown variable")
	if errors.Unwrap(err).Error() != expectedErr.Error() {
		t.Fatalf("unexpexted error, want %q, have %q", expectedErr, errors.Unwrap(err).Error())
	}

	// Try to update undefined rule
	err = p.FromString(`
		SecRule REQUEST_URI|REQUEST_COOKIES "abc" "id:9,phase:2"
		SecRuleUpdateTargetById 99 "!REQUEST_HEADERS:xyz"
	`)
	expectedErr = errors.New("cannot create a variable exception for an undefined rule")
	if errors.Unwrap(err).Error() != expectedErr.Error() {
		t.Fatalf("unexpected error, want %q, have %q", expectedErr, errors.Unwrap(err).Error())
	}
}

func TestDefaultActionsErrors(t *testing.T) {
	testCases := map[string]struct {
		rules string
	}{
		"SecDefaultAction with bad actions": {
			rules: `SecDefaultAction "logauditlog,pass"`,
		},
		"Missing phase": {
			rules: `SecDefaultAction "log,auditlog,pass"`,
		},
		"Bad phase": {
			rules: `SecDefaultAction "phase:A,log,auditlog,pass"`,
		},
		"Missing disruptive action": {
			rules: `SecDefaultAction "phase:1,log,auditlog"`,
		},
		"SecDefaultAction with metadata action": {
			rules: `SecDefaultAction "phase:1,log,auditlog,pass,msg:'metadata action'"`,
		},
		"SecDefaultAction with a transformation": {
			rules: `SecDefaultAction "phase:1,log,auditlog,pass,t:none"`,
		},
		"SecDefaultAction with a transformation uppercase": {
			rules: `SecDefaultAction "phase:1,log,auditlog,pass,T:NoNe"`,
		},
		"Multiple SecDefaultAction for the same phase": {
			rules: `SecDefaultAction "phase:1,log,auditlog,pass"
			SecDefaultAction "phase:1,nolog,noauditlog,pass"`,
		},
	}
	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			dummySecAction := `
			SecAction "id:1,phase:1" `
			waf := corazawaf.NewWAF()
			p := NewParser(waf)
			// SecDefaultActions are parsed only when a rule is parsed, thus we add a dummy SecAction
			err := p.FromString(tCase.rules + dummySecAction)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestDefaultActionsForPhase2Overridable(t *testing.T) {
	waf := corazawaf.NewWAF()
	p := NewParser(waf)
	// A SecDefaultAction at phase:2 defined by the user has to override the hardcoded defaultActionsPhase2
	err := p.FromString(`
	SecDefaultAction "phase:2,nolog,noauditlog,pass"
	SecAction "id:1,noauditlog"
	SecAction "id:2,phase:1"`)
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
	if waf.Rules.GetRules()[0].Log != false {
		t.Error("failed to set log to false")
	}
	if waf.Rules.GetRules()[0].Audit != false {
		t.Error("failed to set audit to false")
	}
	if waf.Rules.GetRules()[1].Log != false {
		t.Error("phase 1 rules shouldn't have log set by default actions of different phases")
	}
	if waf.Rules.GetRules()[1].Audit != false {
		t.Error("phase 1 rules shouldn't have log set by default actions of different phases")
	}
}

func TestDefaultActionsForPhase2(t *testing.T) {
	waf := corazawaf.NewWAF()
	p := NewParser(waf)
	// Via defaultActionsPhase2 variable, the default actions for phase 2 are hardcoded in Coraza.
	// Only a SecDefaultAction of the same phase should override it.
	err := p.FromString(`
	SecDefaultAction "phase:3,log,auditlog,pass"
	SecAction "id:1,phase:2"
	SecAction "id:2,phase:1"`)
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
	if waf.Rules.GetRules()[0].Log != true {
		t.Error("failed to set log to true because of default actions")
	}
	if waf.Rules.GetRules()[0].Audit != true {
		t.Error("failed to set audit to true because of default actions")
	}

	if waf.Rules.GetRules()[1].Log || waf.Rules.GetRules()[1].Audit {
		t.Error("phase 1 rules shouldn't have log set by default actions of different phases")
	}
}

func TestInvalidOperatorRuleData(t *testing.T) {
	tests := []string{
		`ARGS`,
		`ARGS `,
		`ARGS notquoted "deny"`,
		`Args "op`,
		`ARGS "op" notquoted`,
		`Args "op" "`,
		`Args "op" "deny`,
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt, func(t *testing.T) {
			if _, _, _, err := parseActionOperator(tt); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func BenchmarkParseActions(b *testing.B) {
	actionsToBeParsed := "id:980170,phase:5,pass,t:none,noauditlog,msg:'Anomaly Scores:Inbound Scores - Outbound Scores',tag:test"
	for i := 0; i < b.N; i++ {
		_, _ = parseActions(actionsToBeParsed)
	}
}
