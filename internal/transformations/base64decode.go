// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "strings"

var base64DecMap = []byte{
	127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	127, 127, 127, 62, 127, 127, 127, 63, 52, 53,
	54, 55, 56, 57, 58, 59, 60, 61, 127, 127,
	127, 64, 127, 127, 127, 0, 1, 2, 3, 4,
	5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	25, 127, 127, 127, 127, 127, 127, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
	39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
	49, 50, 51, 127, 127, 127, 127, 127,
}

// base64decode decodes a Base64-encoded string.
// Padding is optional.
// Partial decoding is returned up to the first invalid character (if any).
// New line characters (\r and \n) are ignored.
// Note: a custom base64 decoder is used in order to return partial decoding when an error arises. It
// would be possible to use the standard library only relying on undocumented behaviors of the decoder.
// For more context, see https://github.com/corazawaf/coraza/pull/940
func base64decode(data string) (string, bool, error) {
	res := doBase64decode(data)
	return res, true, nil
}

func doBase64decode(src string) string {
	slen := len(src)
	if slen == 0 {
		return src
	}

	var n, x int
	var dst strings.Builder
	dst.Grow(slen)

	for i := 0; i < slen; i++ {
		currChar := src[i]
		// new line characters are ignored.
		if currChar == '\r' || currChar == '\n' {
			continue
		}
		// If invalid character or padding reached, we stop decoding
		if currChar == '=' || currChar == ' ' || currChar > 127 {
			break
		}
		decodedChar := base64DecMap[currChar]
		// Another condition of invalid character
		if decodedChar == 127 {
			break
		}

		x = (x << 6) | int(decodedChar&0x3F)
		n++
		if n == 4 {
			dst.WriteByte(byte(x >> 16))
			dst.WriteByte(byte(x >> 8))
			dst.WriteByte(byte(x))
			n = 0
			x = 0
		}
	}

	// Handle any remaining characters
	if n == 2 {
		x <<= 12
		dst.WriteByte(byte(x >> 16))
	} else if n == 3 {
		x <<= 6
		dst.WriteByte(byte(x >> 16))
		dst.WriteByte(byte(x >> 8))
	}

	return dst.String()
}
