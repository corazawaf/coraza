// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.contains

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type contains struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*contains)(nil)

// Name: contains
// Description: Returns `true` if the parameter string is found anywhere in the input.
// Macro expansion is performed on the parameter string before comparison.
// ---
// Example:
// ```apache
// # Detect ".php" anywhere in the request line
// SecRule REQUEST_LINE "@contains .php" "id:150"
// ```
func newOperatorContains(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
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
	Register("contains", newOperatorContains)
}
