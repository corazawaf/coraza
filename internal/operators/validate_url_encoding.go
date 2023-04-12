// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.validateUrlEncoding

package operators

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type validateURLEncoding struct{}

var _ plugintypes.Operator = (*validateURLEncoding)(nil)

func newValidateURLEncoding(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &validateURLEncoding{}, nil
}

func (o *validateURLEncoding) Evaluate(_ plugintypes.TransactionState, value string) bool {
	if len(value) == 0 {
		return false
	}

	rc := validateURLEncodingInternal(value, len(value))
	switch rc {
	case 1:
		/* Encoding is valid */
		return false
	case -2:
		// Invalid URL Encoding: Non-hexadecimal
		return true
	case -3:
		// Invalid URL Encoding: Not enough characters at the end of input
		return true
	case -1:

	default:
		// Invalid URL Encoding: Internal error
		return true
	}
	return true
}

func validateURLEncodingInternal(input string, inputLen int) int {
	if inputLen == 0 {
		return -1
	}

	var i int
	for i < inputLen {
		if input[i] == '%' {
			if i+2 >= inputLen {
				/* Not enough bytes. */
				return -3
			}
			/* Here we only decode a %xx combination if it is valid,
			 * leaving it as is otherwise.
			 */
			c1 := input[i+1]
			c2 := input[i+2]

			if (((c1 >= '0') && (c1 <= '9')) || ((c1 >= 'a') && (c1 <= 'f')) || ((c1 >= 'A') && (c1 <= 'F'))) && (((c2 >= '0') && (c2 <= '9')) || ((c2 >= 'a') && (c2 <= 'f')) || ((c2 >= 'A') && (c2 <= 'F'))) {
				i += 3
			} else {
				/* Non-hexadecimal characters used in encoding. */
				return -2
			}
		} else {
			i++
		}
	}
	return 1
}

func init() {
	Register("validateUrlEncoding", newValidateURLEncoding)
}
