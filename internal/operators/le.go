// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.le

package operators

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type le struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*le)(nil)

func newLE(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments
	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &le{data: m}, nil
}

func (o *le) Evaluate(tx plugintypes.TransactionState, value string) bool {
	d, _ := strconv.Atoi(o.data.Expand(tx))
	v, _ := strconv.Atoi(value)
	return v <= d
}

func init() {
	Register("le", newLE)
}
