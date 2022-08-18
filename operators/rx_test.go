// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"context"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestRx1(t *testing.T) {
	rx := &rx{}
	opts := coraza.RuleOperatorOptions{
		Arguments: "som(.*)ta",
	}
	if err := rx.Init(opts); err != nil {
		t.Error(err)
	}
	waf := coraza.NewWaf()
	tx := waf.NewTransaction(context.Background())
	tx.Capture = true
	res := rx.Evaluate(tx, "somedata")
	if !res {
		t.Error("rx1 failed")
	}
	/*
		vars := tx.GetCollection(variables.TX).Data()
		if vars["0"][0] != "somedata" {
			t.Error("rx1 failed")
		}
		if vars["1"][0] != "eda" {
			t.Error("rx1 failed")
		}
	*/
}
