// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.validateUtf8Encoding

package operators

import (
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type validateUtf8Encoding struct{}

var _ plugintypes.Operator = (*validateUtf8Encoding)(nil)

func newValidateUTF8Encoding(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &validateUtf8Encoding{}, nil
}

func (o *validateUtf8Encoding) Evaluate(_ plugintypes.TransactionState, value string) bool {
	return !utf8.ValidString(value)
}

func init() {
	Register("validateUtf8Encoding", newValidateUTF8Encoding)
}
