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
		transformedData := doJsDecode(data, i)
		return transformedData, data != transformedData, nil
	}
	return data, false, nil
}

// https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/actions/transformations/js_decode.cc
func doJsDecode(input string, pos int) string {
	d := []byte(input)
	inputLen := len(input)

	i := pos
	c := pos

	for i < inputLen {
		if input[i] == '\\' {
			/* Character is an escape. */

			switch {

			case (i+5 < inputLen) && (input[i+1] == 'u') && (utils.ValidHex(input[i+2])) && (utils.ValidHex(input[i+3])) && (utils.ValidHex(input[i+4])) && (utils.ValidHex(input[i+5])):
				/* \uHHHH */

				/* Use only the lower byte. */
				d[c] = utils.X2c(input[i+4:])

				/* Full width ASCII (ff01 - ff5e) needs 0x20 added */
				if (d[c] > 0x00) && (d[c] < 0x5f) && ((input[i+2] == 'f') || (input[i+2] == 'F')) && ((input[i+3] == 'f') || (input[i+3] == 'F')) {
					d[c] += 0x20
				}

				c++
				i += 6
			case (i+3 < inputLen) && (input[i+1] == 'x') && utils.ValidHex(input[i+2]) && utils.ValidHex(input[i+3]):
				/* \xHH */
				d[c] = utils.X2c(input[i+2:])
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

	return utils.WrapUnsafe(d[:c])

}

func isodigit(x byte) bool {
	return (x >= '0') && (x <= '7')
}
