// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.validateUtf8Encoding

package operators

import (
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Checks whether the input is a valid UTF-8 encoded string. Detects encoding issues,
// malformed sequences, and overlong encodings. Useful for preventing UTF-8 validation
// attacks and ensuring proper character encoding.
//
// Arguments:
// None. Operates on the target variable specified in the rule.
//
// Returns:
// true if invalid UTF-8 encoding is found (violation), false if encoding is valid
//
// Example:
// ```
// # Ensure valid UTF-8 in request parameters
// SecRule ARGS "@validateUtf8Encoding" "id:193,deny,log,msg:'Invalid UTF-8 encoding'"
//
// # Check request body encoding
// SecRule REQUEST_BODY "@validateUtf8Encoding" "id:194,deny"
// ```
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
