// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.detectSQLi

package operators

import (
	"github.com/corazawaf/libinjection-go"

	"github.com/corazawaf/coraza/v3/rules"
)

type detectSQLi struct{}

var _ rules.Operator = (*detectSQLi)(nil)

func newDetectSQLi(rules.OperatorOptions) (rules.Operator, error) {
	return &detectSQLi{}, nil
}

func (o *detectSQLi) Evaluate(tx rules.TransactionState, value string) bool {
	res, fingerprint := libinjection.IsSQLi(value)
	if !res {
		return false
	}
	tx.CaptureField(0, string(fingerprint))
	return true
}

func init() {
	Register("detectSQLi", newDetectSQLi)
}
