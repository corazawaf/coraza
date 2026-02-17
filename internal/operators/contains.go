// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.contains

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Matches if the parameter string is found anywhere in the input.
// Supports macro expansion for dynamic string matching.
//
// Arguments:
// String to search for within the input. Supports variable expansion using %{VAR} syntax.
//
// Returns:
// true if the parameter string is found anywhere in the input, false otherwise
//
// Example:
// ```
// # Detect PHP files in request line
// SecRule REQUEST_LINE "@contains .php" "id:150,deny,log"
//
// # Check if URI contains admin
// SecRule REQUEST_URI "@contains admin" "id:151,deny"
// ```
type contains struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*contains)(nil)

func newContains(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &contains{data: m}, nil
}

func (o *contains) Evaluate(tx plugintypes.TransactionState, value string) bool {
	data := o.data.Expand(tx)
	return strings.Contains(value, data)
}

func init() {
	Register("contains", newContains)
}
