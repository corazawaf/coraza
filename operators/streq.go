// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.streq

package operators

import (
	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
)

type streq struct {
	data macro.Macro
}

func newStrEq(options rules.OperatorOptions) (rules.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &streq{data: m}, nil
}

func (o *streq) Evaluate(tx rules.TransactionState, value string) bool {
	data := o.data.Expand(tx)
	return data == value
}

func init() {
	Register("streq", newStrEq)
}
