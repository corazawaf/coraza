// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type lt struct {
	data corazawaf.Macro
}

func (o *lt) Init(options corazawaf.RuleOperatorOptions) error {
	data := options.Arguments

	macro, err := corazawaf.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = *macro
	return nil
}

func (o *lt) Evaluate(tx *corazawaf.Transaction, value string) bool {
	vv := o.data.Expand(tx)
	data, _ := strconv.Atoi(vv)
	v, _ := strconv.Atoi(value)
	return v < data
}
