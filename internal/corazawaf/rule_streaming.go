// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import "github.com/corazawaf/coraza/v3/types/variables"

// isStreamRecordScopedVariable reports whether v is repopulated for each record of a
// streaming body (see processRequestBodyStreaming and processResponseBodyStreaming),
// as opposed to a variable like REQUEST_HEADERS or REQUEST_COOKIES that stays constant
// across records. It is used to skip re-evaluating non-record-scoped variables after
// the first record.
//
// Known limitation: a chained rule whose root level targets only a non-record-scoped
// variable will only be able to enter its chain on the first record, since the root is
// skipped (and so never "matches" to continue the chain) on later records. This doesn't
// occur in the CRS ruleset today — its content-inspection rules combine record- and
// non-record-scoped variables in a single non-chained rule rather than across chain
// levels — but a user-authored ruleset could hit it. Fixing it requires tracking
// per-chain "root already matched" state across Eval calls, which is a larger change
// than this fix's scope.
func isStreamRecordScopedVariable(v variables.RuleVariable) bool {
	switch v {
	case variables.Args, variables.ArgsPost, variables.ArgsNames, variables.ArgsPostNames, variables.ArgsCombinedSize:
		// Repopulated from ArgsPost on each request body record.
		return true
	case variables.ResponseArgs:
		// Repopulated on each response body record.
		return true
	default:
		return false
	}
}
