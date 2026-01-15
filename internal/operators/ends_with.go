// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.endsWith

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Matches if the parameter string appears at the end of the input.
// Supports macro expansion for dynamic string matching.
//
// Arguments:
// String to match at the end of the input. Supports variable expansion using %{VAR} syntax.
//
// Returns:
// true if the input ends with the parameter string, false otherwise
//
// Example:
// ```
// # Block requests that don't end with HTTP/1.1
// SecRule REQUEST_LINE "!@endsWith HTTP/1.1" "id:152,deny,log"
//
// # Check if filename ends with .exe
// SecRule REQUEST_FILENAME "@endsWith .exe" "id:154,deny"
// ```
type endsWith struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*endsWith)(nil)

func newEndsWith(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &endsWith{data: m}, nil
}

func (o *endsWith) Evaluate(tx plugintypes.TransactionState, value string) bool {
	data := o.data.Expand(tx)
	return strings.HasSuffix(value, data)
}

func init() {
	Register("endsWith", newEndsWith)
}
