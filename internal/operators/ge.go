// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.ge

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/plugins"
	"github.com/corazawaf/coraza/v3/rules"
)

type ge struct {
	data macro.Macro
}

var _ rules.Operator = (*ge)(nil)

func newGE(options rules.OperatorOptions) (rules.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &ge{data: m}, nil
}

func (o *ge) Evaluate(tx rules.TransactionState, value string) bool {
	v, _ := strconv.Atoi(value)
	data, _ := strconv.Atoi(o.data.Expand(tx))
	return v >= data
}

func init() {
	plugins.RegisterOperator("ge", newGE)
}
