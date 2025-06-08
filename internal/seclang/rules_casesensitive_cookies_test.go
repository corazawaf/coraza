// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.rule.case_sensitive_args_keys

package seclang

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestCaseSensitiveCookieRuleMatchRegex(t *testing.T) {
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

func TestCaseSensitiveCookies(t *testing.T) {
	waf := corazawaf.NewWAF()
	rules := `SecRule ARGS:Test1 "Xyz" "id:3, phase:2, log, deny"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction()
	tx.ProcessRequestHeaders()
	tx.AddPostRequestArgument("Test1", "Xyz")
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Errorf("failed to test arguments value match: Same case argument name, %+v\n", tx.MatchedRules())
	}

	tx = waf.NewTransaction()
	tx.ProcessRequestHeaders()
	tx.AddPostRequestArgument("TEST1", "Xyz")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Errorf("failed to test arguments value match: argument is matching a different case, %+v\n", tx.MatchedRules())
	}

	tx = waf.NewTransaction()
	tx.ProcessRequestHeaders()
	tx.AddPostRequestArgument("Test1", "XYZ")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Errorf("failed to test arguments value match: argument is matching a different case, %+v\n", tx.MatchedRules())
	}
}
