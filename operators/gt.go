// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
)

type gt struct {
	data macro.Macro
}

var _ rules.Operator = (*gt)(nil)

func (o *gt) Init(options rules.OperatorOptions) error {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = m
	return nil
}

func (o *gt) Evaluate(tx rules.TransactionState, value string) bool {
	v, _ := strconv.Atoi(value)
	k, _ := strconv.Atoi(o.data.Expand(tx))
	return k < v
}
