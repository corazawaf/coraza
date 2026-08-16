// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strconv"
	"strings"

	utils "github.com/corazawaf/coraza/v3/internal/strings"
)

func jsDecode(data string) (string, bool, error) {
	if i := strings.IndexByte(data, '\\'); i != -1 {
		// TODO: This will transform even if the backslash isn't followed by an escape,
		// but keep it simple for now.
		transformedData, changed := doJsDecode(data, i)
		return transformedData, changed, nil
	}
	return data, false, nil
}

// https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/actions/transformations/js_decode.cc
func doJsDecode(input string, pos int) (string, bool) {
	d := []byte(input)
	inputLen := len(input)
	changed := false

	i := pos
	c := pos

	for i < inputLen {
		if input[i] == '\\' {
			/* Character is an escape. */

			/* Measured once here rather than in the case guard below, which
			 * would otherwise have to repeat the scan to recover the length. */
			extLen := 0
			if (i+2 < inputLen) && (input[i+1] == 'u') && (input[i+2] == '{') {
				extLen = jsExtendedUnicodeEscapeLen(input, i+3)
			}

			switch {

			case extLen > 0:
				/* \u{H...H} - ES2015+ extended Unicode code point escape
				 * (1-6 hex digits). Handled the same way as \uHHHH below:
				 * lower byte of the value, with the same full-width-ASCII
				 * fold -- checked against the fully resolved value, not a
				 * fixed digit count, so a leading-zero encoding (e.g.
				 * \u{0ff01}) folds the same as \u{ff01}. */
				j := extLen

				var code rune
				for k := 0; k < j; k++ {
					code = code<<4 | rune(xsingle2c(input[i+3+k]))
				}

				/* Use only the lower byte. */
				d[c] = byte(code)
				changed = true

				/* Full width ASCII (ff01 - ff5e) needs 0x20 added */
				if (code >= 0xff01) && (code <= 0xff5e) {
					d[c] += 0x20
				}

				c++
				i += j + 4 // '\', 'u', '{', j hex digits, '}'

			case (i+5 < inputLen) && (input[i+1] == 'u') && (utils.ValidHex(input[i+2])) && (utils.ValidHex(input[i+3])) && (utils.ValidHex(input[i+4])) && (utils.ValidHex(input[i+5])):
				/* \uHHHH */

				/* Use only the lower byte. */
				d[c] = utils.X2c(input[i+4:])
				changed = true

				/* Full width ASCII (ff01 - ff5e) needs 0x20 added */
				if (d[c] > 0x00) && (d[c] < 0x5f) && ((input[i+2] == 'f') || (input[i+2] == 'F')) && ((input[i+3] == 'f') || (input[i+3] == 'F')) {
					d[c] += 0x20
					changed = true
				}

				c++
				i += 6
			case (i+3 < inputLen) && (input[i+1] == 'x') && utils.ValidHex(input[i+2]) && utils.ValidHex(input[i+3]):
				/* \xHH */
				d[c] = utils.X2c(input[i+2:])
				changed = true
				c++
				i += 4
			case (i+1 < inputLen) && isodigit(input[i+1]):
				/* \OOO (only one byte, \000 - \377) */
				buf := make([]byte, 3)
				j := 0

				for (i+1+j < inputLen) && (j < 3) {
					buf[j] = input[i+j]
					j++
					if !isodigit(input[i+j]) {
						break
					}
				}
				buf = buf[:j]

				if j > 0 {
					/* Do not use 3 characters if we will be > 1 byte */
					if (j == 3) && (buf[0] > '3') {
						j = 2
						buf = buf[:j]
					}
					nn, _ := strconv.ParseInt(string(buf), 8, 8)
					d[c] = byte(nn)
					changed = true
					c++
					i += 1 + j
				}
			case i+1 < inputLen:
				/* \C */
				cc := input[i+1]
				switch input[i+1] {
				case 'a':
					cc = '\a'
				case 'b':
					cc = '\b'
				case 'f':
					cc = '\f'
				case 'n':
					cc = '\n'
				case 'r':
					cc = '\r'
				case 't':
					cc = '\t'
				case 'v':
					cc = '\v'
					/* The remaining (\?,\\,\',\") are just a removal
					 * of the escape char which is default.
					 */
				}

				d[c] = cc
				changed = true
				c++
				i += 2
			default:
				/* Not enough bytes */
				for i < inputLen {
					d[c] = input[i]
					c++
					i++
				}
			}
		} else {
			d[c] = input[i]
			c++
			i++
		}
	}

	return utils.WrapUnsafe(d[:c]), changed

}

func isodigit(x byte) bool {
	return (x >= '0') && (x <= '7')
}

// jsExtendedUnicodeEscapeLen returns the number of hex digits (1-6) in a
// \u{H...H} escape whose first hex digit is at pos, or 0 if the escape is
// malformed (no digits, more than 6 digits, or missing the closing '}').
func jsExtendedUnicodeEscapeLen(input string, pos int) int {
	inputLen := len(input)
	j := 0
	for (j < 6) && (pos+j < inputLen) && utils.ValidHex(input[pos+j]) {
		j++
	}
	if (j == 0) || (pos+j >= inputLen) || (input[pos+j] != '}') {
		return 0
	}
	return j
}
