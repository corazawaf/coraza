// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/rules"
)

type validateUtf8Encoding struct{}

var _ rules.Operator = (*validateUtf8Encoding)(nil)

func newValidateUTF8Encoding(rules.OperatorOptions) (rules.Operator, error) {
	return &validateUtf8Encoding{}, nil
}

func (o *validateUtf8Encoding) Evaluate(_ rules.TransactionState, value string) bool {
	return !utf8.ValidString(value)
}
