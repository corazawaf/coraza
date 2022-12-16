// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.within

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/operators"
	"github.com/corazawaf/coraza/v3/rules"
)

type within struct {
	data macro.Macro
}

func newWithin(options rules.OperatorOptions) (rules.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &within{data: m}, nil
}

func (o *within) Evaluate(tx rules.TransactionState, value string) bool {
	data := o.data.Expand(tx)
	return strings.Contains(data, value)
}

func init() {
	operators.Register("within", newWithin)
}
