// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	stringsutil "github.com/corazawaf/coraza/v3/internal/strings"
)

func lowerCase(data string) (string, bool, error) {
	// TODO: Explicit implementation of ToLower would allow optimizing away the byte by byte comparison for returning the changed boolean
	// See https://github.com/corazawaf/coraza/pull/778#discussion_r1186963422
	transformedData := stringsutil.AsciiToLower(data)
	return transformedData, data != transformedData, nil
}
