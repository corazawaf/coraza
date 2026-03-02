// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.eq

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Performs numerical comparison and returns true if the input value is equal to the provided parameter.
// Both values are converted to integers before comparison. Supports macro expansion for dynamic comparison.
//
// Arguments:
// Integer value to compare against. Supports variable expansion using %{VAR} syntax.
//
// Returns:
// true if the input value equals the parameter value numerically, false otherwise
//
// Example:
// ```
// # Check if request header count is exactly 15
// SecRule &REQUEST_HEADERS_NAMES "@eq 15" "id:153,deny,log"
//
// # Compare parameter value to expected number
// SecRule ARGS:quantity "@eq 100" "id:154,pass"
// ```
type eq struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*eq)(nil)

func newEq(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
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
	Register("eq", newEq)
}
