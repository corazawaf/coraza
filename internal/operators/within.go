// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.within

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Returns true if the input value (the needle) is found anywhere within the @within parameter (the haystack).
// This is the inverse of contains - it checks if the input is contained in the parameter list.
// Supports macro expansion for dynamic matching.
//
// Arguments:
// Comma-separated list of values to search within. Supports variable expansion using %{VAR} syntax.
//
// Returns:
// true if the input value is found in the parameter list, false otherwise
//
// Example:
// ```
// # Allow only specific HTTP methods
// SecRule REQUEST_METHOD "!@within GET,POST,HEAD" "id:178,deny,log"
//
// # Check if parameter value is in allowed list
// SecRule ARGS:action "@within view,list,search" "id:179,pass"
// ```
type within struct {
	data macro.Macro
}

func newWithin(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &within{data: m}, nil
}

func (o *within) Evaluate(tx plugintypes.TransactionState, value string) bool {
	data := o.data.Expand(tx)
	return strings.Contains(data, value)
}

func init() {
	Register("within", newWithin)
}
