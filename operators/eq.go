// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/macro"
)

type eq struct {
	data macro.Macro
}

var _ corazawaf.RuleOperator = (*eq)(nil)

func (o *eq) Init(options corazawaf.RuleOperatorOptions) error {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = m
	return nil
}

func (o *eq) Evaluate(tx *corazawaf.Transaction, value string) bool {
	d1, _ := strconv.Atoi(o.data.Expand(tx))
	d2, _ := strconv.Atoi(value)
	return d1 == d2
}
