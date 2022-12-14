// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"unicode"
)

func compressWhitespace(value string) (string, error) {
	var a []byte
	i := 0
	inWhiteSpace := false
	length := len(value)

	for i < length {
		if unicode.IsSpace(rune(value[i])) {
			if inWhiteSpace {
				i++
				continue
			} else {
				inWhiteSpace = true
				a = append(a, ' ')
			}
		} else {
			inWhiteSpace = false
			a = append(a, value[i])
		}
		i++
	}

	return string(a), nil
}
