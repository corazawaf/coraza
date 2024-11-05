// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"github.com/corazawaf/coraza/v3/internal/strings"
)

func compressWhitespace(value string) (string, bool, error) {
	for i := 0; i < len(value); i++ {
		if isLatinSpace(value[i]) {
			transformedValue, changed := doCompressWhitespace(value, i)
			return transformedValue, changed, nil
		}
	}
	return value, false, nil
}

func doCompressWhitespace(input string, pos int) (string, bool) {
	// The output may be significantly different in length (shorter) than the input, so we don't preallocate
	ret := []byte(input[0:pos])

	changed := false
	inWhiteSpace := false
	for i := pos; i < len(input); {
		if isLatinSpace(input[i]) {
			if inWhiteSpace {
				i++
				changed = true
				continue
			} else {
				inWhiteSpace = true
				ret = append(ret, ' ')
			}
		} else {
			inWhiteSpace = false
			ret = append(ret, input[i])
		}
		i++
	}

	return strings.WrapUnsafe(ret), changed
}

func isLatinSpace(c byte) bool { // copied from unicode.IsSpace
	switch c {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x85, 0xA0:
		return true
	}
	return false
}
