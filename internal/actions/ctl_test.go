// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	_ "github.com/corazawaf/coraza/v3/internal/auditlog"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestCtl(t *testing.T) {
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()
	r := corazawaf.NewRule()
	a := ctl()

	bodyprocessors := []string{"XML", "JSON", "URLENCODED", "MULTIPART"}
	for _, bp := range bodyprocessors {
		if err := a.Init(r, "requestBodyProcessor="+bp); err != nil {
			t.Errorf("failed to init requestBodyProcessor %s", bp)
		}
		a.Evaluate(r, tx)
		if tx.Variables().RequestBodyProcessor().Get() != bp {
			t.Error("failed to set RequestBodyProcessor " + bp)
		}
	}

	if err := a.Init(r, "ruleRemoveTargetById=981260;ARGS:user"); err != nil {
		t.Error("failed to init ruleRemoveTargetById=981260;ARGS:user")
	}
	a.Evaluate(r, tx)
	/*
		TODO
		if tx.ruleRemoveTargetById[981260] == nil {
			t.Error("Failed to create ruleRemoveTargetById")
		} else {
			if tx.ruleRemoveTargetById[981260][0].Collection != coraza.VARIABLE_ARGS {
				t.Error("Failed to create ruleRemoveTargetById, invalid Collection")
			}
			if tx.ruleRemoveTargetById[981260][0].Key != "user" {
				t.Error("Failed to create ruleRemoveTargetById, invalid Key")
			}
		}
	*/

	if err := a.Init(r, "auditEngine=Off"); err != nil {
		t.Error("failed to init ctl with auditEngine=Off")
	}
	a.Evaluate(r, tx)

	if tx.AuditEngine != types.AuditEngineOff {
		t.Error("Failed to disable audit log")
	}

	if err := a.Init(r, "ruleEngine=Off"); err != nil {
		t.Error("failed to init ctl using ruleEngine=Off")
	}
	a.Evaluate(r, tx)

	if tx.RuleEngine != types.RuleEngineOff {
		t.Errorf("Failed to disable rule engine, got %s", tx.RuleEngine.String())
	}

	if err := a.Init(r, "requestBodyLimit=12345"); err != nil {
		t.Error("failed to init ctl with requestBodyLimit=12345")
	}
	a.Evaluate(r, tx)

	if tx.RequestBodyLimit != 12345 {
		t.Error("Failed to set request body limit")
	}
}

func TestParseCtl(t *testing.T) {
	tCases := []struct {
		input            string
		expectAction     ctlFunctionType
		expectValue      string
		expectCollection variables.RuleVariable
		expectKey        string
	}{
		{"ruleRemoveTargetByTag=MY_TAG;ARGS:user", ctlRuleRemoveTargetByTag, "MY_TAG", variables.Args, "user"},
		{"ruleRemoveTargetById=2;REQUEST_FILENAME:", ctlRuleRemoveTargetByID, "2", variables.RequestFilename, ""},
		{"ruleRemoveTargetById=8888;REMOTE_PORT", ctlRuleRemoveTargetByID, "8888", variables.RemotePort, ""},
	}
	for _, tCase := range tCases {
		t.Run(tCase.input, func(t *testing.T) {
			action, value, collection, colKey, err := parseCtl(tCase.input)
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			if action != tCase.expectAction {
				t.Errorf("unexpected action, want: %d, have: %d", tCase.expectAction, action)
			}
			if value != tCase.expectValue {
				t.Errorf("unexpected value, want: %s, have: %s", tCase.expectValue, value)
			}
			if collection != tCase.expectCollection {
				t.Errorf("unexpected collection, want: %s, have: %s", tCase.expectCollection.Name(), collection.Name())
			}
			if colKey != tCase.expectKey {
				t.Errorf("unexpected key, want: %s, have: %s", tCase.expectKey, colKey)
			}
		})
	}

}
func TestCtlParseRange(t *testing.T) {
	rules := []*corazawaf.Rule{
		{
			RuleMetadata: corazarules.RuleMetadata{
				ID_: 5,
			},
		},
		{
			RuleMetadata: corazarules.RuleMetadata{
				ID_: 15,
			},
		},
	}

	tCases := []struct {
		_range              string
		expectedNumberOfIds int
		expectErr           bool
	}{
		{"1-2", 0, false},
		{"4-5", 1, false},
		{"4-15", 2, false},
		{"5", 1, false},
		{"", 0, true},
		{"test", 0, true},
		{"test-2", 0, true},
		{"2-test", 0, true},
		{"-", 0, true},
		{"4-5-15", 0, true},
	}
	for _, tCase := range tCases {
		t.Run(tCase._range, func(t *testing.T) {
			ints, err := rangeToInts(rules, tCase._range)
			if tCase.expectErr && err == nil {
				t.Error("expected error for range")
			}

			if !tCase.expectErr && err != nil {
				t.Errorf("unexpected error for range: %s", err.Error())
			}

			if !tCase.expectErr && len(ints) != tCase.expectedNumberOfIds {
				t.Error("unexpected number of ids")
			}
		})
	}
}

func TestParseOnOff(t *testing.T) {
	tCases := []struct {
		val         string
		expectedVal bool
		expectedOK  bool
	}{
		{"on", true, true},
		{"ON", true, true},
		{"On", true, true},
		{"off", false, true},
		{"OFF", false, true},
		{"Off", false, true},
		{"Whatever", false, false},
	}

	for _, tCase := range tCases {
		t.Run(tCase.val, func(t *testing.T) {
			val, ok := parseOnOff(tCase.val)
			if want, have := tCase.expectedOK, ok; want != have {
				t.Errorf("unexpected OK, want: %t, have: %t", want, have)
			}
			if want, have := tCase.expectedVal, val; want != have {
				t.Errorf("unexpected value, want: %t, have: %t", want, have)
			}
		})
	}
}
