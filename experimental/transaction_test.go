// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental_test

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
)

func TestTxTimestamp(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		panic(err)
	}
	tx := waf.NewTransaction()
	tx2, ok := tx.(experimental.Transaction)
	if !ok {
		t.Error("Transaction does not implement experimental.Transaction")
	}
	if tx2.UnixTimestamp() == 0 {
		t.Error("Timestamp should not be 0")
	}
}
