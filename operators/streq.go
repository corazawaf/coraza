// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3"
)

type streq struct {
	data coraza.Macro
}

var _ coraza.RuleOperator = (*streq)(nil)

func (o *streq) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments

	macro, err := coraza.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = *macro
	return nil
}

func (o *streq) Evaluate(tx *coraza.Transaction, value string) bool {
	data := o.data.Expand(tx)
	return data == value
}
