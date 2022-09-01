// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"context"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestRestPath(t *testing.T) {
	waf := coraza.NewWAF()
	tx := waf.NewTransaction(context.Background())
	exp := "/some-random/url-{id}/{name}"
	path := "/some-random/url-123/juan"
	rp := restpath{}
	if err := rp.Init(coraza.RuleOperatorOptions{
		Arguments: exp,
	}); err != nil {
		t.Error(err)
	}
	if !rp.Evaluate(tx, path) {
		t.Errorf("Expected %s to match %s", exp, path)
	}
	if tx.Variables.ArgsPath.Get("id")[0] != "123" {
		t.Errorf("Expected 123, got %s", tx.Variables.ArgsPath.Get("id"))
	}
}
