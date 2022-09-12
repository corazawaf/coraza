// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/macro"
)

type lt struct {
	data macro.Macro
}

func (o *lt) Init(options corazawaf.RuleOperatorOptions) error {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = m
	return nil
}

func (o *lt) Evaluate(tx *corazawaf.Transaction, value string) bool {
	vv := o.data.Expand(tx)
	data, _ := strconv.Atoi(vv)
	v, _ := strconv.Atoi(value)
	return v < data
}
