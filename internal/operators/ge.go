// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.ge

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Returns true if the input value is greater than or equal to the provided parameter.
// Both values are converted to integers before comparison. Supports macro expansion for dynamic comparison.
//
// Arguments:
// Integer value to compare against. Supports variable expansion using %{VAR} syntax.
//
// Returns:
// true if the input value is greater than or equal to the parameter value, false otherwise
//
// Example:
// ```
// # Block if too many request headers
// SecRule &REQUEST_HEADERS_NAMES "@ge 15" "id:155,deny,log"
//
// # Check minimum value requirement
// SecRule ARGS:age "@ge 18" "id:156,pass"
// ```
type ge struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*ge)(nil)

func newGE(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
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
	Register("ge", newGE)
}
