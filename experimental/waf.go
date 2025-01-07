// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"io"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// WAF IMPORTANT: This interface is experimental and may change in the future
// WAF v4 interface supports creating transactions with options and
// closing the WAF instance to release resources
// This interface will replace coraza.WAF in v4
type WAF interface {
	coraza.WAF
	io.Closer
	// NewTransactionWithOptions creates a new initialized transaction for this WAF instance
	NewTransactionWithOptions(coraza.Options) types.Transaction
}
