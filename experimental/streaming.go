// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"io"

	"github.com/corazawaf/coraza/v3/types"
)

// StreamingTransaction extends Transaction with streaming body processing capabilities.
// Transactions created by a WAF instance implement this interface when the WAF supports
// streaming body processors (e.g., NDJSON, JSON-Seq).
//
// Unlike the standard ProcessRequestBody/ProcessResponseBody methods which require the
// full body to be buffered first, streaming methods read records directly from input,
// evaluate rules per record, and write clean records to output for relay to the backend.
type StreamingTransaction interface {
	types.Transaction

	// ProcessRequestBodyFromStream reads records from input, evaluates Phase 2 rules
	// per record, and writes clean records to output. If a record triggers an interruption,
	// processing stops and the interruption is returned.
	//
	// For non-streaming body processors, this falls back to buffering the input,
	// processing it normally, and copying the result to output.
	ProcessRequestBodyFromStream(input io.Reader, output io.Writer) (*types.Interruption, error)

	// ProcessResponseBodyFromStream reads records from input, evaluates Phase 4 rules
	// per record, and writes clean records to output.
	ProcessResponseBodyFromStream(input io.Reader, output io.Writer) (*types.Interruption, error)
}
