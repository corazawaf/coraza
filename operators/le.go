// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
)

type le struct {
	data macro.Macro
}

var _ rules.RuleOperator = (*le)(nil)

func (o *le) Init(options rules.RuleOperatorOptions) error {
	data := options.Arguments
	m, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = m
	return nil
}

func (o *le) Evaluate(tx rules.TransactionState, value string) bool {
	d, _ := strconv.Atoi(o.data.Expand(tx))
	v, _ := strconv.Atoi(value)
	return v <= d
}
