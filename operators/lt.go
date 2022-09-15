// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
)

type lt struct {
	data macro.Macro
}

var _ rules.Operator = (*lt)(nil)

func (o *lt) Init(options rules.OperatorOptions) error {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = m
	return nil
}

func (o *lt) Evaluate(tx rules.TransactionState, value string) bool {
	vv := o.data.Expand(tx)
	data, _ := strconv.Atoi(vv)
	v, _ := strconv.Atoi(value)
	return v < data
}
