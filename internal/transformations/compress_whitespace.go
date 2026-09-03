// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

func compressWhitespace(value string) (string, bool, error) {
	for i, r := range value {
		if isLatinSpace(r) || value[i] == rawNBSP {
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
		// Å, ą, 你). Byte-level matching corrupted those characters by
		// matching on that trailing byte alone.
		r, size := utf8.DecodeRuneInString(input[i:])
		if isLatinSpace(r) || input[i] == rawNBSP {
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

// rawNBSP is a bare 0xA0 byte: a Latin-1 non-breaking space that is not part
// of a valid UTF-8 sequence. 0xA0 (0b1010_0000) always falls in the UTF-8
// continuation-byte range (0x80-0xBF), so it can never be a valid *leading*
// byte -- seen at a rune boundary, it is unambiguously a stray byte rather
// than the start of some other character.
//
// ModSecurity's compressWhitespace matches this byte directly regardless of
// encoding (`#define NBSP 160`), and Coraza transforms arbitrary request
// bytes rather than guaranteed-UTF-8 strings, so it must still collapse --
// otherwise input like "SELECT\xa01" would reach the operator unnormalized.
// Raw 0x85 is deliberately not given the same treatment: isspace() in the C
// locale ModSecurity uses never matched it, so byte-matching it would be
// ModSecurity-parity we don't actually want.
const rawNBSP = 0xA0

// isLatinSpace reports whether r is one of the ASCII whitespace characters
// or U+00A0 (NBSP) / U+0085 (NEL) -- the Latin-1 subset of unicode.IsSpace
// that ModSecurity's compressWhitespace matches. It deliberately does not
// cover the rest of unicode.IsSpace (U+2000-U+200A, U+2028, U+3000, etc.);
// removeWhitespace uses the full unicode.IsSpace and so differs from this
// function on those runes.
func isLatinSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x85, 0xA0:
		return true
	}
	return false
}
