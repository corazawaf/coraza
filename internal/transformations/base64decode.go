// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"encoding/base64"

	stringsutil "github.com/corazawaf/coraza/v3/internal/strings"
)

// base64decode decodes a Base64-encoded string.
func base64decode(data string) (string, bool, error) {
	dec, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		// Forgiving implementation, which ignores invalid characters
		return data, false, nil
	}
	return stringsutil.WrapUnsafe(dec), true, nil
}
