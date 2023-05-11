// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strings"
	"unicode"
)

// removeWhitespace removes all whitespace characters from input.
func removeWhitespace(data string) (string, bool, error) {
	changed := false
	transformedData := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			// if the character is a space, drop it
			changed = true
			return -1
		}
		// else keep it in the string
		return r
	}, data)

	return transformedData, changed, nil
}
