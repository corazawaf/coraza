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
	data macro.Macro
}

var _ plugintypes.Operator = (*eq)(nil)

// Name: eq
// Description: Performs numerical comparison and returns true if the input value is equal
// to the provided parameter. Macro expansion is performed on the parameter string before comparison.
// ---
// Example:
// ```apache
// # Detect exactly 15 request headers
// SecRule &REQUEST_HEADERS_NAMES "@eq 15" "id:153"
// ```
//
// Note: If a value is provided that cannot be converted to an integer (i.e a string) this operator will
// treat that value as `0`.
func newOperatorEq(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &eq{data: m}, nil
}

func (o *eq) Evaluate(tx plugintypes.TransactionState, value string) bool {
	d1, _ := strconv.Atoi(o.data.Expand(tx))
	d2, _ := strconv.Atoi(value)
	return d1 == d2
}

func init() {
	Register("eq", newOperatorEq)
}
