// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3"
)

type validateUtf8Encoding struct{}

func (o *validateUtf8Encoding) Init(options coraza.RuleOperatorOptions) error {
	return nil
}

func (o *validateUtf8Encoding) Evaluate(tx *coraza.Transaction, value string) bool {
	return utf8.ValidString(value)
}
