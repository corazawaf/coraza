// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3"
)

type eq struct {
	data coraza.Macro
}

func (o *eq) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments

	macro, err := coraza.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = *macro
	return nil
}

func (o *eq) Evaluate(tx *coraza.Transaction, value string) bool {
	d1, err := strconv.Atoi(o.data.Expand(tx))
	if err != nil {
		d1 = 0
	}
	d2, err := strconv.Atoi(value)
	if err != nil {
		d2 = 0
	}
	return d1 == d2
}
