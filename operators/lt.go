// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3"
)

type lt struct {
	data coraza.Macro
}

func (o *lt) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments

	macro, err := coraza.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = *macro
	return nil
}

func (o *lt) Evaluate(tx *coraza.Transaction, value string) bool {
	vv := o.data.Expand(tx)
	data, err := strconv.Atoi(vv)
	if err != nil {
		data = 0
	}
	v, err := strconv.Atoi(value)
	if err != nil {
		v = 0
	}
	return v < data
}
