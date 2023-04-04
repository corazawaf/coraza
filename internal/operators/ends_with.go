// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.endsWith

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type endsWith struct {
	data macro.Macro
}

var _ plugintypes.Operator = (*endsWith)(nil)

func newEndsWith(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	m, err := macro.NewMacro(data)
	if err != nil {
		return nil, err
	}
	return &endsWith{data: m}, nil
}

func (o *endsWith) Evaluate(tx plugintypes.TransactionState, value string) bool {
	data := o.data.Expand(tx)
	return strings.HasSuffix(value, data)
}

func init() {
	Register("endsWith", newEndsWith)
}
