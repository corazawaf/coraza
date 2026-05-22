// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.validateUrlEncoding

package operators

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Validates URL-encoded characters in the input string. Checks that percent-encoding
// follows proper format (%XX where X is a hexadecimal digit). Returns true if invalid
// encoding is detected (non-hex characters or incomplete sequences).
//
// Arguments:
// None. Operates on the target variable specified in the rule.
//
// Returns:
// true if invalid URL encoding is found (violation), false if encoding is valid
//
// Example:
// ```
// # Ensure proper URL encoding in request URI
// SecRule REQUEST_URI_RAW "@validateUrlEncoding" "id:191,deny,log,msg:'Invalid URL encoding'"
//
// # Check query string encoding
// SecRule QUERY_STRING "@validateUrlEncoding" "id:192,deny"
// ```
type validateURLEncoding struct{}

var _ plugintypes.Operator = (*validateURLEncoding)(nil)

func newValidateURLEncoding(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &validateURLEncoding{}, nil
}

func (o *validateURLEncoding) Evaluate(_ plugintypes.TransactionState, value string) bool {
	if len(value) == 0 {
		return false
	}
	rc := validateURLEncodingInternal(value)
	// rc valute might be used for more detailed logging, but the operator so far only
	// returns true/false for violation detection, so we consider any non-1 return value as a violation.
	// Return value mapping:
	// 1: Valid encoding
	// -2: Invalid URL Encoding: Non-hexadecimal
	// -3: Invalid URL Encoding: Not enough characters at the end of input
	return rc != 1
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func validateURLEncodingInternal(input string) int {
	inputLen := len(input)
	if inputLen == 0 {
		return -1
	}

	i := 0
	for i < inputLen {
		if input[i] != '%' {
			i++
			continue
		}
		if i+2 >= inputLen {
			// Not enough bytes after '%' for a valid encoding sequence
			return -3
		}
		if !isHexDigit(input[i+1]) || !isHexDigit(input[i+2]) {
			// Non-hexadecimal characters used in encoding.
			return -2
		}
		i += 3
	}
	return 1
}

func init() {
	Register("validateUrlEncoding", newValidateURLEncoding)
}
