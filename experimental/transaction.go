// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import "github.com/corazawaf/coraza/v3/types"

type Transaction interface {
	types.Transaction
	UnixTimestamp() int64
}
