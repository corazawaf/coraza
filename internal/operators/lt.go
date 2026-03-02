// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.lt

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Returns true if the input value is less than the operator parameter.
// Both values are converted to integers before comparison. Supports macro expansion for dynamic comparison.
//
// Arguments:
// Integer value to compare against. Supports variable expansion using %{VAR} syntax.
//
// Returns:
// true if the input value is less than the parameter value, false otherwise
//
// Example:
// ```
// # Ensure header count stays below threshold
// SecRule &REQUEST_HEADERS_NAMES "@lt 15" "id:166,pass,log"
//
// # Check value is under limit
// SecRule ARGS:quantity "@lt 1000" "id:167,pass"
// ```
type lt struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*lt)(nil)

func newLT(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &lt{data: m}, nil
}

func (o *lt) Evaluate(tx plugintypes.TransactionState, value string) bool {
	vv := o.data.Expand(tx)
	data, _ := strconv.Atoi(vv)
	v, _ := strconv.Atoi(value)
	return v < data
}

func init() {
	Register("lt", newLT)
}
