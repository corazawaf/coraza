// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.rule.case_sensitive_args_keys

package seclang

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestCaseSensitiveArgsRuleMatchRegex(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On
		SecRule ARGS:/^Key/ "@streq my-value" "id:1028,phase:1,deny,status:403,msg:'ARGS:key matched.'"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.ProcessURI("https://asdf.com/index.php?t1=aaa&T1=zzz&t2=bbb&t3=ccc&Keyless=my-value&a=test&jsessionid=74B0CB414BD77D17B5680A6386EF1666", "GET", "HTTP/1.1")
	tx.ProcessConnection("127.0.0.1", 0, "", 0)
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules()) != 1 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules()))
	}
	if tx.Interruption() == nil {
		t.Fatal("failed to interrupt transaction")
	}
}

func TestCaseSensitivePostArguments(t *testing.T) {
	tests := []struct {
		name         string
		rule         string
		argPostKey   string
		argPostValue string
		expectMatch  bool
	}{
		{
			name:         "Arg key and operator matching case sensitivity",
			rule:         `SecRule ARGS:Test1 "Xyz" "id:3, phase:2, log, deny"`,
			argPostKey:   "Test1",
			argPostValue: "Xyz",
			expectMatch:  true,
		},
		{
			name:         "Arg key uppercase with post key lowercase",
			rule:         `SecRule ARGS:Test1 "Xyz" "id:3, phase:2, log, deny"`,
			argPostKey:   "TEST1",
			argPostValue: "Xyz",
			expectMatch:  false,
		},
		{
			name:         "Arg key marching case sensitivity, match not",
			rule:         `SecRule ARGS:Test1 "Xyz" "id:3, phase:2, log, deny"`,
			argPostKey:   "Test1",
			argPostValue: "XYZ",
			expectMatch:  false,
		},
		{
			name:         "ARGS_NAMES expected to be case-sensitive. Test1 should exist",
			rule:         `SecRule ARGS_NAMES "Test1" "id:1, phase:2, log, deny"`,
			argPostKey:   "Test1",
			argPostValue: "Xyz",
			expectMatch:  true,
		},
		{
			name:         "ARGS_NAMES expected to be case-sensitive. TEST1 should not exist",
			rule:         `SecRule ARGS_NAMES "TEST1" "id:1, phase:2, log, deny"`,
			argPostKey:   "Test1",
			argPostValue: "Xyz",
			expectMatch:  false,
		},
		{
			name:         "ARGS_NAMES expected to be case-sensitive. TEST1 with case sensitivity (?i) regex should match",
			rule:         `SecRule ARGS_NAMES "@rx (?i)TEST1" "id:1, phase:2, log, deny"`,
			argPostKey:   "Test1",
			argPostValue: "Xyz",
			expectMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := corazawaf.NewWAF()
			parser := NewParser(waf)

			err := parser.FromString(tt.rule)
			if err != nil {
				t.Fatalf("failed to parse rule: %v", err)
			}
			tx := waf.NewTransaction()
			tx.ProcessRequestHeaders()
			tx.AddPostRequestArgument(tt.argPostKey, tt.argPostValue)
			it, err := tx.ProcessRequestBody()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.expectMatch && it == nil {
				t.Errorf("expected a match but got none")
			}
			if !tt.expectMatch && it != nil {
				t.Errorf("expected no match but got: %+v", tx.MatchedRules()[0])
			}
		})
	}
}

func TestCaseSensitiveURIQueryParam(t *testing.T) {
	waf := corazawaf.NewWAF()
	rules := `SecRule ARGS:Test1 "@contains SQLI" "id:3, phase:2, log, pass"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction()
	tx.ProcessURI("/url?Test1='SQLI", "POST", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	_, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}

	if len(tx.MatchedRules()) == 1 {
		if len(tx.MatchedRules()[0].MatchedDatas()) != 1 {
			t.Errorf("failed to test uri query param. Found matches: %d, %+v\n",
				len(tx.MatchedRules()[0].MatchedDatas()), tx.MatchedRules())
		}
		if !isMatchData(tx.MatchedRules()[0].MatchedDatas(), "Test1") {
			t.Error("Key did not match: Test1 !=", tx.MatchedRules()[0])
		}
	} else {
		t.Errorf("failed to test uri query param: Same case arg name: %d, %+v\n",
			len(tx.MatchedRules()), tx.MatchedRules())
	}

	tx = waf.NewTransaction()
	tx.ProcessURI("/test?test1='SQLI&Test1='SQLI&TEST1='SQLI", "POST", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	_, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}

	if len(tx.MatchedRules()) == 1 {
		if len(tx.MatchedRules()[0].MatchedDatas()) != 1 {
			t.Errorf("failed to test uri query param. Found matches: %d, %+v\n",
				len(tx.MatchedRules()[0].MatchedDatas()), tx.MatchedRules())
		}
		if !isMatchData(tx.MatchedRules()[0].MatchedDatas(), "Test1") {
			t.Error("Key did not match: Test1 !=", tx.MatchedRules()[0])
		}
	} else {
		t.Errorf("failed to test qparam pollution: Multiple arg different case: %d, %+v\n",
			len(tx.MatchedRules()), tx.MatchedRules())
	}
}
