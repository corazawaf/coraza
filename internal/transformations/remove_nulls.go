// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strings"
)

// removeNulls removes NUL bytes in input.
func removeNulls(data string) (string, bool, error) {
	transformedData := strings.ReplaceAll(data, "\x00", "")
	return transformedData, len(data) != len(transformedData), nil
}
