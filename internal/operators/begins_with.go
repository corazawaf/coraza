// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.beginsWith

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Matches if the parameter string appears at the beginning of the input.
// Supports macro expansion for dynamic string matching.
//
// Arguments:
// String to match at the start of the input. Supports variable expansion using %{VAR} syntax.
//
// Returns:
// true if the input starts with the parameter string, false otherwise
//
// Example:
// ```
// # Block requests that don't start with GET
// SecRule REQUEST_LINE "!@beginsWith GET" "id:149,deny,log"
//
// # Check if URI starts with /admin
// SecRule REQUEST_URI "@beginsWith /admin" "id:150,deny"
// ```
type beginsWith struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*beginsWith)(nil)

func newBeginsWith(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &beginsWith{data: m}, nil
}

func (o *beginsWith) Evaluate(tx plugintypes.TransactionState, value string) bool {
	data := o.data.Expand(tx)
	return strings.HasPrefix(value, data)
}

func init() {
	Register("beginsWith", newBeginsWith)
}
