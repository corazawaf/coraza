// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.eq

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type eq struct {
	macro.Macro
}

var _ plugintypes.Operator = (*eq)(nil)

// Description: Performs numerical comparison and returns true if the input value is equal to
// the provided parameter. Macro expansion is performed on the parameter string before comparison.
// ---
// Example:
// ```apache
// # Detect exactly 15 request headers
// SecRule &REQUEST_HEADERS_NAMES "@eq 15" "id:153"
// ```
// Note: If a value is provided that cannot be converted to an integer (i.e a string) this operator
// will treat that value as 0.
func newEq(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &eq{Macro: m}, nil
}

func (o *eq) Evaluate(tx plugintypes.TransactionState, value string) bool {
	// if values can't be converted to int, they are interpreted as 0
	// see https://github.com/owasp-modsecurity/ModSecurity/blob/3748d62/src/operators/eq.cc#L37-L41
	d1, _ := strconv.Atoi(o.Macro.Expand(tx))
	d2, _ := strconv.Atoi(value)
	return d1 == d2
}

func init() {
	Register("eq", newEq)
}
