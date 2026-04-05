// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"io"

	"github.com/corazawaf/coraza/v3/types"
)

// StreamingTransaction extends Transaction with streaming body processing capabilities.
// It is used by integrators building streaming middleware where the full body should
// not be buffered before rule evaluation.
//
// Unlike the standard ProcessRequestBody/ProcessResponseBody methods which buffer the
// entire body first, streaming methods read records directly from input, evaluate rules
// per record, and write clean records to output for relay to the backend. The body
// processor defines what constitutes a "record" (a JSON object, a CSV row, a protobuf
// message, etc.).
//
// # Execution model
//
// Both methods execute synchronously on the caller's goroutine. The call chain is:
//
//	caller goroutine → ProcessRequestBodyFromStream → sp.ProcessRequestRecords → per-record Rules.Eval
//
// There is no hidden concurrency. In the standard Go HTTP model (net/http), each
// request owns its goroutine, so other requests are not blocked — but this request's
// response is delayed until all records have been evaluated (or one triggers an
// interruption).
//
// The [types.Transaction] is not safe for concurrent use. Records within a single
// phase must be evaluated sequentially. ArgsPost/ResponseArgs are cleared per record,
// while TX-scoped variables (e.g., anomaly scores) persist across records for
// cross-record correlation.
//
// # Phase ordering and full-duplex limitations
//
// Coraza follows the ModSecurity phase model where request processing (Phases 1–2)
// must complete before response processing (Phases 3–4) begins. This means:
//
//   - ProcessRequestBodyFromStream must finish before ProcessResponseBodyFromStream
//     can be called on the same transaction.
//   - Full-duplex streaming — where a client writes request records while
//     simultaneously reading response records (e.g., LLM token streaming over
//     NDJSON) — is NOT supported within a single transaction. The request body
//     must be fully evaluated before response evaluation can begin.
//   - Calling both methods concurrently on the same transaction is undefined
//     behavior and will corrupt transaction state.
//
// Integrators needing concurrent bidirectional streaming should evaluate whether
// the WAF inspection model is appropriate for their use case, or consider
// inspecting only one direction (e.g., request-only for prompt injection
// detection in LLM proxies).
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
	//
	// This method must not be called until ProcessRequestBodyFromStream (or
	// ProcessRequestBody) has returned, as Phase 2 must complete before Phase 4.
	ProcessResponseBodyFromStream(input io.Reader, output io.Writer) (*types.Interruption, error)
}
