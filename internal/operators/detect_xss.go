// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.detectXSS

package operators

import (
	"github.com/corazawaf/libinjection-go"

	"github.com/corazawaf/coraza/v3/rules"
)

type detectXSS struct{}

var _ rules.Operator = (*detectXSS)(nil)

func newDetectXSS(rules.OperatorOptions) (rules.Operator, error) {
	return &detectXSS{}, nil
}

func (o *detectXSS) Evaluate(_ rules.TransactionState, value string) bool {
	return libinjection.IsXSS(value)
}

func init() {
	Register("detectXSS", newDetectXSS)
}
