// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.eq

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
)

type eq struct {
	data macro.Macro
}

var _ rules.Operator = (*eq)(nil)

func newEq(options rules.OperatorOptions) (rules.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &eq{data: m}, nil
}

func (o *eq) Evaluate(tx rules.TransactionState, value string) bool {
	d1, _ := strconv.Atoi(o.data.Expand(tx))
	d2, _ := strconv.Atoi(value)
	return d1 == d2
}

func init() {
	Register("eq", newEq)
}
