// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/macro"
)

type endsWith struct {
	data macro.Macro
}

var _ corazawaf.RuleOperator = (*endsWith)(nil)

func (o *endsWith) Init(options corazawaf.RuleOperatorOptions) error {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = m
	return nil
}

func (o *endsWith) Evaluate(tx *corazawaf.Transaction, value string) bool {
	data := o.data.Expand(tx)
	return strings.HasSuffix(value, data)
}
