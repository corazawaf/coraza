// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.detectSQLi

package operators

import (
	"github.com/corazawaf/libinjection-go"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Detects SQL injection attacks using libinjection library. Returns true if SQL injection
// payload is found in the input. Captures the SQLi fingerprint in field 0 for logging and analysis.
//
// Arguments:
// None. Operates on the target variable specified in the rule.
//
// Returns:
// true if SQL injection is detected, false otherwise
//
// Example:
// ```
// # Detect SQLi in query string
// SecRule ARGS "@detectSQLi" "id:185,deny,log,msg:'SQL Injection Detected'"
//
// # Check request body for SQLi
// SecRule REQUEST_BODY "@detectSQLi" "id:186,deny"
// ```
type detectSQLi struct{}

var _ plugintypes.Operator = (*detectSQLi)(nil)

func newDetectSQLi(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &detectSQLi{}, nil
}

func (o *detectSQLi) Evaluate(tx plugintypes.TransactionState, value string) bool {
	res, fingerprint := libinjection.IsSQLi(value)
	if !res {
		return false
	}
	tx.CaptureField(0, fingerprint)
	return true
}

func init() {
	Register("detectSQLi", newDetectSQLi)
}
