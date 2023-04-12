// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.ge

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type ge struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*ge)(nil)

func newGE(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &ge{data: m}, nil
}

func (o *ge) Evaluate(tx plugintypes.TransactionState, value string) bool {
	v, _ := strconv.Atoi(value)
	data, _ := strconv.Atoi(o.data.Expand(tx))
	return v >= data
}

func init() {
	Register("ge", newGE)
}
