// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/libinjection-go"

	"github.com/corazawaf/coraza/v3/rules"
)

type detectXSS struct{}

var _ rules.Operator = (*detectXSS)(nil)

func (o *detectXSS) Init(rules.OperatorOptions) error { return nil }

func (o *detectXSS) Evaluate(_ rules.TransactionState, value string) bool {
	return libinjection.IsXSS(value)
}
