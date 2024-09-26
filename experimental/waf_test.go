// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental_test

import (
	"fmt"

	"github.com/redwanghb/coraza/v3"
	"github.com/redwanghb/coraza/v3/experimental"
)

func ExampleWAFWithOptions_NewTransactionWithOptions() {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		panic(err)
	}

	oWAF, ok := waf.(experimental.WAFWithOptions)
	if !ok {
		panic("WAF does not implement WAFWithOptions")
	}

	tx := oWAF.NewTransactionWithOptions(experimental.Options{
		ID: "abc123",
	})

	fmt.Println("Transaction ID:", tx.ID())

	// Output:
	// Transaction ID: abc123
}
