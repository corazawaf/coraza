// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.strmatch

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Performs case-sensitive substring matching to check if the parameter string appears anywhere in the input.
// This operator is compatible with ModSecurity's @strmatch operator. Supports macro expansion for dynamic string matching.
// To perform case-insensitive matching, use the t:lowercase transformation.
//
// Arguments:
// String to search for within the input. Supports variable expansion using %{VAR} syntax.
//
// Returns:
// true if the parameter string is found anywhere in the input, false otherwise
//
// Example:
// ```
// # Block requests with WebZIP user agent
// SecRule REQUEST_HEADERS:User-Agent "@strmatch WebZIP" "id:1,deny"
//
// # Detect suspicious patterns in URI
// SecRule REQUEST_URI "@strmatch ../../../" "id:2,deny,log"
// ```
type strmatch struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*strmatch)(nil)

func newStrmatch(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &strmatch{data: m}, nil
}

func (o *strmatch) Evaluate(tx plugintypes.TransactionState, value string) bool {
	data := o.data.Expand(tx)
	return strings.Contains(value, data)
}

func init() {
	Register("strmatch", newStrmatch)
}
