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
			// Forgiving call to DecodeString, decoding is performed up to the illegal characther
			// If an error occurs, dec will still contain the decoded string up to the error
			dec, _ = base64.RawStdEncoding.DecodeString(dataNoPadding[:illegalCharPos])
		} else {
			return data, false, nil
		}
	}
	return stringsutil.WrapUnsafe(dec), true, nil
}
