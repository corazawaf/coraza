// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/libinjection-go"

	"github.com/corazawaf/coraza/v3"
)

type detectXSS struct{}

var _ coraza.RuleOperator = (*detectXSS)(nil)

func (o *detectXSS) Init(coraza.RuleOperatorOptions) error { return nil }

func (o *detectXSS) Evaluate(_ *coraza.Transaction, value string) bool {
	return libinjection.IsXSS(value)
}
