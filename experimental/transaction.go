// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"github.com/corazawaf/coraza/v3/types"
)

type Transaction interface {
	types.Transaction
	// UseRequestBody directly sets the provided byte slice as the request body buffer.
	// This is meant to be used when the entire request body is available, as it avoids
	// the need for an extra copy into the request body buffer. Because of this, this method
	// is expected to be called just once, further calls to UseRequestBody have to be avoided.
	// If the body size exceeds the limit and the action is to reject, an interruption will be returned.
	// The caller should not use b slice after this call.
	//
	// It returns the relevant interruption, the final internal body buffer length and any error that occurs.
	UseRequestBody(b []byte) (*types.Interruption, int, error)

	UseResponseBody(b []byte) (*types.Interruption, int, error)
}
