// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.detectXSS

package operators

import (
	"github.com/corazawaf/libinjection-go"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Detects Cross-Site Scripting (XSS) attacks using libinjection library. Returns true if
// XSS payload is found in the input. Uses advanced pattern matching to identify XSS vectors.
//
// Arguments:
// None. Operates on the target variable specified in the rule.
//
// Returns:
// true if XSS injection is detected, false otherwise
//
// Example:
// ```
// # Detect XSS in request parameters
// SecRule ARGS "@detectXSS" "id:187,deny,log,msg:'XSS Attack Detected'"
//
// # Check request body for XSS
// SecRule REQUEST_BODY "@detectXSS" "id:188,deny"
// ```
type detectXSS struct{}

var _ plugintypes.Operator = (*detectXSS)(nil)

func newDetectXSS(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &detectXSS{}, nil
}

func (o *detectXSS) Evaluate(_ plugintypes.TransactionState, value string) bool {
	return libinjection.IsXSS(value)
}

func init() {
	Register("detectXSS", newDetectXSS)
}
