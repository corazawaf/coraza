// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import "github.com/corazawaf/coraza/v3/types"

type Transaction interface {
	// UnixTimestamp returns the timestamp when the request was received.
	UnixTimestamp() int64
	types.Transaction
}
