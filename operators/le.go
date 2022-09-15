// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3"
)

type le struct {
	data coraza.Macro
}

var _ coraza.RuleOperator = (*le)(nil)

func (o *le) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments
	macro, err := coraza.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = *macro
	return nil
}

func (o *le) Evaluate(tx *coraza.Transaction, value string) bool {
	d, _ := strconv.Atoi(o.data.Expand(tx))
	v, _ := strconv.Atoi(value)
	return v <= d
}
