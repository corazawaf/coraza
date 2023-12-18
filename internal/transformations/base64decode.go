// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "strings"

// // base64decode decodes a Base64-encoded string.
// func base64decode(data string) (string, bool, error) {
// 	// RawStdEncoding.DecodeString accepts and requires an unpadded string as input
// 	// https://stackoverflow.com/questions/31971614/base64-encode-decode-without-padding-on-golang-appengine
// 	dataNoPadding := strings.TrimRight(data, "=")
// 	dec, err := base64.RawStdEncoding.DecodeString(dataNoPadding)
// 	if err != nil {
// 		// If the error is of type CorruptInputError, we can get the position of the illegal character
// 		// and perform a partial decoding up to that point
// 		if corrErr, ok := err.(base64.CorruptInputError); ok {
// 			illegalCharPos := int(corrErr)
// 			// Forgiving call (no error check) to DecodeString. Decoding is performed truncating
// 			// the input string to the first error index. If a new decoding error occurs,
// 			// it will not be about an illegal character but a malformed encoding of the trailing
// 			// character because of the truncation. The dec will still contain a best effort decoded string
// 			dec, _ = base64.RawStdEncoding.DecodeString(dataNoPadding[:illegalCharPos])
// 		} else {
// 			return data, false, nil
// 		}
// 	}
// 	return stringsutil.WrapUnsafe(dec), true, nil
// }

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
// Important: We cannot use the golang base64 package because it does not
// support mixed content like RAW+BASE64+RAW
// This implementations supports base64 between non-base64 content
func base64decode(data string) (string, bool, error) {
	res := doBase64decode(data)
	return res, true, nil
}

func doBase64decode(src string) string {
	slen := len(src)
	if slen == 0 {
		return src
	}

	var n, x, srcc int
	var dst strings.Builder
	dst.Grow(slen)

	for ; srcc < slen; srcc++ {
		// If invalid characther or padding reached, we stop decoding
		if src[srcc] == '=' || src[srcc] == ' ' || src[srcc] > 127 || base64DecMap[src[srcc]] == 127 {
			break
		}
		if src[srcc] == '\r' || src[srcc] == '\n' {
			continue
		}

		x = (x << 6) | int(base64DecMap[src[srcc]]&0x3F)
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
