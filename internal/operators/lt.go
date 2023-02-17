// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.lt

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/plugins"
	"github.com/corazawaf/coraza/v3/rules"
)

type lt struct {
	data macro.Macro
}

var _ rules.Operator = (*lt)(nil)

func newLT(options rules.OperatorOptions) (rules.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &lt{data: m}, nil
}

func (o *lt) Evaluate(tx rules.TransactionState, value string) bool {
	vv := o.data.Expand(tx)
	data, _ := strconv.Atoi(vv)
	v, _ := strconv.Atoi(value)
	return v < data
}

func init() {
	plugins.RegisterOperator("lt", newLT)
}
