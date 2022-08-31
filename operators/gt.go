// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3"
)

type gt struct {
	data coraza.Macro
}

func (o *gt) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments

	macro, err := coraza.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = *macro
	return nil
}

func (o *gt) Evaluate(tx *coraza.Transaction, value string) bool {
	v, _ := strconv.Atoi(value)
	k, _ := strconv.Atoi(o.data.Expand(tx))
	return k < v
}
