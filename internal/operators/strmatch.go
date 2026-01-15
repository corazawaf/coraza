// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.strmatch

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// strmatch performs string matching using substring search.
//
// The operator performs case-sensitive substring matching using Go's
// strings.Contains function. To perform case-insensitive matching, use the
// t:lowercase transformation.
//
// Example usage:
//
//	SecRule REQUEST_HEADERS:User-Agent "@strmatch WebZIP" "id:1,deny"
//
// This operator is intended to be compatible with ModSecurity's @strmatch
// operator in terms of behavior.
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
