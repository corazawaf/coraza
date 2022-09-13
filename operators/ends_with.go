// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3"
)

type endsWith struct {
	data coraza.Macro
}

var _ coraza.RuleOperator = (*endsWith)(nil)

func (o *endsWith) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments

	macro, err := coraza.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = *macro
	return nil
}

func (o *endsWith) Evaluate(tx *coraza.Transaction, value string) bool {
	data := o.data.Expand(tx)
	return strings.HasSuffix(value, data)
}
