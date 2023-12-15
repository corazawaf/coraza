// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"encoding/base64"
	"strings"

	stringsutil "github.com/corazawaf/coraza/v3/internal/strings"
)

// base64decode decodes a Base64-encoded string.
func base64decode(data string) (string, bool, error) {
	// RawStdEncoding.DecodeString accepts and requires an unpadded string as input
	// https://stackoverflow.com/questions/31971614/base64-encode-decode-without-padding-on-golang-appengine
	dataNoPadding := strings.TrimRight(data, "=")
	dec, err := base64.RawStdEncoding.DecodeString(dataNoPadding)
	if err != nil {
		// If the error is of type CorruptInputError, we can get the position of the illegal character
		// and perform a partial decoding up to that point
		if corrErr, ok := err.(base64.CorruptInputError); ok {
			illegalCharPos := int(corrErr)
			// Forgiving call (no error check) to DecodeString. Decoding is performed truncating
			// the input string to the first error index. If a new decoding error occurs,
			// it will not be about an illegal character but a malformed encoding of the trailing
			// character because of the truncation. The dec will still contain a best effort decoded string
			dec, _ = base64.RawStdEncoding.DecodeString(dataNoPadding[:illegalCharPos])
		} else {
			return data, false, nil
		}
	}
	return stringsutil.WrapUnsafe(dec), true, nil
}
