// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3"
	engine "github.com/corazawaf/coraza/v3"
)

type ge struct {
	data coraza.Macro
}

func (o *ge) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments

	macro, err := coraza.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = *macro
	return nil
}

func (o *ge) Evaluate(tx *engine.Transaction, value string) bool {
	v, err := strconv.Atoi(value)
	if err != nil {
		v = 0
	}
	data := o.data.Expand(tx)
	dataint, err := strconv.Atoi(data)
	if err != nil {
		dataint = 0
	}
	return v >= dataint
}
