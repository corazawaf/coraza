// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"context"

	"github.com/corazawaf/coraza/v3/types"
)

type Transaction interface {
	types.Transaction
	// UnixTimestamp returns the Unix timestamp of the transaction
	UnixTimestamp() int64
	// Context returns the context of the transaction
	Context() context.Context
}
