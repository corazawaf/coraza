// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transformations

import (
	"strconv"

	utils "github.com/jptosso/coraza-waf/v2/utils/strings"
)

func escapeSeqDecode(input string) (string, error) {
	var i, count, d int
	inputLen := len(input)
	data := []byte(input)

	for i < inputLen {
		if (input[i] == '\\') && (i+1 < inputLen) {
			c := -1

			switch input[i+1] {
			case 'a':
				c = '\a'
			case 'b':
				c = '\b'
			case 'f':
				c = '\f'
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			case 'v':
				c = '\v'
			case '\\':
				c = '\\'
			case '?':
				c = '?'
			case '\'':
				c = '\''
			case '"':
				c = '"'
			}

			if c != -1 {
				i += 2
			}

			/* Hexadecimal or octal? */
			if c == -1 {
				if (input[i+1] == 'x') || (input[i+1] == 'X') {
					/* Hexadecimal. */
					if (i+3 < inputLen) && (utils.ValidHex((input[i+2]))) && (utils.ValidHex((input[i+3]))) {
						/* Two digits. */
						c = int(utils.X2c(input[i+2:]))
						i += 4
					}
					/* Else Invalid encoding, do nothing. */

				} else {
					if isODigit(input[i+1]) { /* Octal. */
						buf := make([]byte, 4)
						j := 0

						for (i+1+j < inputLen) && (j < 3) {
							buf[j] = input[i+1+j]
							j++
							if (len(input) > (i + 1 + j)) && !isODigit(input[i+1+j]) {
								break
							}
						}
						// buf[j] = '\x00'
						// This line actually means that the string ends here so:
						buf = buf[:j]

						if j > 0 {
							bc, _ := strconv.ParseInt(string(buf), 8, 32)
							c = int(bc)
							i += 1 + j
						}
					}
				}
			}

			if c == -1 {
				/* Didn't recognise encoding, copy raw bytes. */
				data[d] = input[i+1]
				d++
				count++
				i += 2
			} else {
				/* Converted the encoding. */
				data[d] = byte(c)
				d++
				count++
			}
		} else {
			/* Input character not a backslash, copy it. */
			data[d] = input[i]
			d++
			i++
			count++
		}
	}
	return string(data[:count]), nil
}

func isODigit(c byte) bool {
	return (c >= '0') && (c <= '7')
}
