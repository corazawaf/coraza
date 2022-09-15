// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
)

type beginsWith struct {
	data macro.Macro
}

var _ rules.Operator = (*beginsWith)(nil)

func (o *beginsWith) Init(options rules.OperatorOptions) error {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = m
	return nil
}

func (o *beginsWith) Evaluate(tx rules.TransactionState, value string) bool {
	data := o.data.Expand(tx)
	return strings.HasPrefix(value, data)
}
