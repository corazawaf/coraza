// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/libinjection-go"
)

type detectXSS struct {
}

func (o *detectXSS) Init(options coraza.RuleOperatorOptions) error {
	return nil
}

func (o *detectXSS) Evaluate(tx *coraza.Transaction, value string) bool {
	return libinjection.IsXSS(value)
}
