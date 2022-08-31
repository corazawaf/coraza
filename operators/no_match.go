// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3"
)

type noMatch struct{}

func (o *noMatch) Init(options coraza.RuleOperatorOptions) error { return nil }

func (o *noMatch) Evaluate(tx *coraza.Transaction, value string) bool {
	return false
}
