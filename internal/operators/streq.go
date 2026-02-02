// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.streq

package operators

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Performs a string comparison and returns true if the parameter string is identical to the input string.
// This is a case-sensitive exact match operator. Supports macro expansion for dynamic string matching.
//
// Arguments:
// String for exact comparison. Supports variable expansion using %{VAR} syntax.
//
// Returns:
// true if the input string is identical to the parameter string, false otherwise
//
// Example:
// ```
// # Block if foo parameter is not exactly "bar"
// SecRule ARGS:foo "!@streq bar" "id:176,deny,log"
//
// # Check if request method is exactly POST
// SecRule REQUEST_METHOD "@streq POST" "id:177,deny"
// ```
type streq struct {
	data macro.Macro
}

func newStrEq(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &streq{data: m}, nil
}

func (o *streq) Evaluate(tx plugintypes.TransactionState, value string) bool {
	data := o.data.Expand(tx)
	return data == value
}

func init() {
	Register("streq", newStrEq)
}
