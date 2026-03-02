// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.gt

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Returns true if the input value is greater than the operator parameter.
// Both values are converted to integers before comparison. Supports macro expansion for dynamic comparison.
//
// Arguments:
// Integer value to compare against. Supports variable expansion using %{VAR} syntax.
//
// Returns:
// true if the input value is greater than the parameter value, false otherwise
//
// Example:
// ```
// # Deny if request header count exceeds limit
// SecRule &REQUEST_HEADERS_NAMES "@gt 15" "id:158,deny,log"
//
// # Check if quantity exceeds threshold
// SecRule ARGS:count "@gt 100" "id:159,deny"
// ```
type gt struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*gt)(nil)

func newGT(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &gt{data: m}, nil
}

func (o *gt) Evaluate(tx plugintypes.TransactionState, value string) bool {
	v, _ := strconv.Atoi(value)
	k, _ := strconv.Atoi(o.data.Expand(tx))
	return k < v
}

func init() {
	Register("gt", newGT)
}
