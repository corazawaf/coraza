// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestWAFWithOptions(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	oWAF, ok := waf.(WAF)
	if !ok {
		t.Fatal("WAF does not implement WAF v4")
	}

	tx := oWAF.NewTransactionWithOptions(coraza.Options{
		ID: "abc123",
	})

	if tx.ID() != "abc123" {
		t.Error("Transaction ID not set")
	}

	// Output:
	// Transaction ID: abc123
}
