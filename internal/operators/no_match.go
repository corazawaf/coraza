// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.noMatch

package operators

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type noMatch struct{}

var _ plugintypes.Operator = (*noMatch)(nil)

func newNoMatch(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &noMatch{}, nil
}

func (*noMatch) Evaluate(tx plugintypes.TransactionState, value string) bool { return false }

func init() {
	Register("noMatch", newNoMatch)
}
