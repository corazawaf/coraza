// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import "github.com/corazawaf/coraza/v3/internal/corazawaf"

type Transaction struct {
	corazawaf.Transaction
}

// UnixTimestamp returns the timestamp when the request was received.
func (tx *Transaction) UnixTimestamp() int64 {
	return tx.Timestamp
}
