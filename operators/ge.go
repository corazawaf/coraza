// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/macro"
)

type ge struct {
	data macro.Macro
}

var _ corazawaf.RuleOperator = (*ge)(nil)

func (o *ge) Init(options corazawaf.RuleOperatorOptions) error {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = m
	return nil
}

func (o *ge) Evaluate(tx *corazawaf.Transaction, value string) bool {
	v, _ := strconv.Atoi(value)
	data, _ := strconv.Atoi(o.data.Expand(tx))
	return v >= data
}
