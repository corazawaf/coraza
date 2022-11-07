// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package jwtop

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestOperator(t *testing.T) {
	cfg := coraza.NewWAFConfig().WithDirectives(`
SecRule REQUEST_HEADERS:Authorization "@jwt hmac secret" "id:1,phase:1"
SecRule ARGS_POST:jwt.claims.name "@rx ^John$" "id:2,phase:1,log"
	`)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	tx.AddRequestHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules()) > 0 {
		mr := tx.MatchedRules()[0]
		if mr.Rule().ID() != 2 {
			t.Fatal("Rule 2 should have matched")
		}
	} else {
		t.Fatal("No rules matched")
	}

}
