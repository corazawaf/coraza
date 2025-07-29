// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.ge

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type ge struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*ge)(nil)

// Name: ge
// Description: Performs numerical comparison and returns true if the input value is greater than or equal
// to the provided parameter. Macro expansion is performed on the parameter string before comparison.
// ---
// Example:
// ```apache
// # Detect 15 or more request headers
// SecRule &REQUEST_HEADERS_NAMES "@ge 15" "id:154"
// ```
//
// Note: If a value is provided that cannot be converted to an integer (i.e a string) this operator will
// treat that value as `0`.
func newOperatorGE(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &ge{data: m}, nil
}

func (o *ge) Evaluate(tx plugintypes.TransactionState, value string) bool {
	v, _ := strconv.Atoi(value)
	data, _ := strconv.Atoi(o.data.Expand(tx))
	return v >= data
}

func init() {
	Register("ge", newOperatorGE)
}
