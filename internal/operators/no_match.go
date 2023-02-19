// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.noMatch

package operators

import (
	"github.com/corazawaf/coraza/v3/plugins"
	"github.com/corazawaf/coraza/v3/rules"
)

type noMatch struct{}

var _ rules.Operator = (*noMatch)(nil)

func newNoMatch(options rules.OperatorOptions) (rules.Operator, error) {
	return &noMatch{}, nil
}

func (*noMatch) Evaluate(tx rules.TransactionState, value string) bool { return false }

func init() {
	plugins.RegisterOperator("noMatch", newNoMatch)
}
