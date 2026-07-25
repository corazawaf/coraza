// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

func compressWhitespace(value string) (string, bool, error) {
	for i, r := range value {
		if isLatinSpace(r) {
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
		// Decode a full rune rather than indexing a single byte: U+0085 and
		// U+00A0 are multi-byte in UTF-8, and the raw bytes 0x85/0xA0 also
		// occur as the trailing byte of many unrelated characters (e.g. à,
		// Å, ą). Byte-level matching corrupted those characters by matching
		// on that trailing byte alone.
		r, size := utf8.DecodeRuneInString(input[i:])
		if isLatinSpace(r) {
			if inWhiteSpace {
				changed = true
			} else {
				inWhiteSpace = true
				if r != ' ' {
					changed = true
				}
				ret = append(ret, ' ')
			}
		} else {
			inWhiteSpace = false
			ret = append(ret, input[i:i+size]...)
		}
		i += size
	}

	return strings.WrapUnsafe(ret), changed
}

func isLatinSpace(r rune) bool { // copied from unicode.IsSpace
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x85, 0xA0:
		return true
	}
	return false
}
