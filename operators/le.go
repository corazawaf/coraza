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
	data := o.data.Expand(tx)
	d, _ := strconv.Atoi(data)
	v, err := strconv.Atoi(value)
	if err != nil {
		v = 0
	}
	return v <= d
}
