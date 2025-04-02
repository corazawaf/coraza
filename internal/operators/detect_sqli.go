// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.detectSQLi

package operators

import (
	"github.com/corazawaf/libinjection-go"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type detectSQLi struct{}

var _ plugintypes.Operator = (*detectSQLi)(nil)

// Name: detectSQLi
// Description: Returns true if SQL injection payload is found. This operator uses LibInjection
// to detect SQLi attacks.
// ---
// Example:
// ```apache
// # Detect SQL Injection inside request uri data"
// SecRule REQUEST_URI "@detectSQLi" "id:152"
// ```
func newOperatorDetectSQLi(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
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
	Register("detectSQLi", newOperatorDetectSQLi)
}
