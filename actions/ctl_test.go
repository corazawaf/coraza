// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"context"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
)

func TestCtl(t *testing.T) {
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction(context.Background())
	r := corazawaf.NewRule()
	ctlf := ctl()

	if err := ctlf.Init(r, "requestBodyProcessor=XML"); err != nil {
		t.Error("Failed to init requestBodyProcessor=XML")
	}
	ctlf.Evaluate(r, tx)
	// Not implemented yet

	if err := ctlf.Init(r, "ruleRemoveTargetById=981260;ARGS:user"); err != nil {
		t.Error("failed to init ruleRemoveTargetById=981260;ARGS:user")
	}
	ctlf.Evaluate(r, tx)
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

	if err := ctlf.Init(r, "auditEngine=Off"); err != nil {
		t.Error("failed to init ctl with auditEngine=Off")
	}
	ctlf.Evaluate(r, tx)

	if tx.AuditEngine != types.AuditEngineOff {
		t.Error("Failed to disable audit log")
	}

	if err := ctlf.Init(r, "ruleEngine=Off"); err != nil {
		t.Error("failed to init ctl using ruleEngine=Off")
	}
	ctlf.Evaluate(r, tx)

	if tx.RuleEngine != types.RuleEngineOff {
		t.Errorf("Failed to disable rule engine, got %s", tx.RuleEngine.String())
	}

	if err := ctlf.Init(r, "requestBodyLimit=12345"); err != nil {
		t.Error("failed to init ctl with requestBodyLimit=12345")
	}
	ctlf.Evaluate(r, tx)

	if tx.RequestBodyLimit != 12345 {
		t.Error("Failed to set request body limit")
	}

	bodyprocessors := []string{"XML", "JSON", "URLENCODED", "MULTIPART"}
	for _, bp := range bodyprocessors {
		if err := ctlf.Init(r, "requestBodyProcessor="+bp); err != nil {
			t.Errorf("failed to init requestBodyProcessor %s", bp)
		}
		ctlf.Evaluate(r, tx)
		if tx.Variables.ReqbodyProcessor.String() != bp {
			t.Error("failed to set RequestBodyProcessor " + bp)
		}
	}
}

func TestCtlParseRange(t *testing.T) {
	a := &ctlFn{}
	rules := []*corazawaf.Rule{
		{
			RuleMetadata: types.RuleMetadata{
				ID: 5,
			},
		},
		{
			RuleMetadata: types.RuleMetadata{
				ID: 15,
			},
		},
	}
	ints, err := a.rangeToInts(rules, "1-2")
	if err != nil {
		t.Error("Failed to parse range")
	}
	if len(ints) != 0 {
		t.Error("Failed to parse range")
	}
	ints, err = a.rangeToInts(rules, "4-5")
	if err != nil {
		t.Error("Failed to parse range")
	}
	if len(ints) != 1 {
		t.Error("Failed to parse range")
	}
	ints, err = a.rangeToInts(rules, "4-15")
	if err != nil {
		t.Error("Failed to parse range")
	}
	if len(ints) != 2 {
		t.Error("Failed to parse range")
	}
	ints, err = a.rangeToInts(rules, "5")
	if err != nil {
		t.Error("Failed to parse range")
	}
	if len(ints) != 1 {
		t.Error("Failed to parse range")
	}
	_, err = a.rangeToInts(rules, "test")
	if err == nil {
		t.Error("Failed to parse range")
	}
}
