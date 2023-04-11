// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.within

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

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
