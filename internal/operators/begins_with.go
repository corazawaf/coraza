// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.beginsWith

package operators

import (
	"strings"

	"github.com/redwanghb/coraza/v3/experimental/plugins/macro"
	"github.com/redwanghb/coraza/v3/experimental/plugins/plugintypes"
)

type beginsWith struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*beginsWith)(nil)

func newBeginsWith(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &beginsWith{data: m}, nil
}

func (o *beginsWith) Evaluate(tx plugintypes.TransactionState, value string) bool {
	data := o.data.Expand(tx)
	return strings.HasPrefix(value, data)
}

func init() {
	Register("beginsWith", newBeginsWith)
}
