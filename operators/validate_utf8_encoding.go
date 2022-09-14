// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3"
)

type validateUtf8Encoding struct{}

var _ coraza.RuleOperator = (*validateUtf8Encoding)(nil)

func (o *validateUtf8Encoding) Init(coraza.RuleOperatorOptions) error { return nil }

func (o *validateUtf8Encoding) Evaluate(_ *coraza.Transaction, value string) bool {
	return utf8.ValidString(value)
}
