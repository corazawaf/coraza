// Copyright 2021 Juan Pablo Tosso
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
	"github.com/jptosso/coraza-waf/pkg/utils"
	"strconv"
)

func EscapeSeqDecode(input string) string {
	var i, count, d int
	input_len := len(input)
	data := []byte(input)

	for i < input_len {
		if (input[i] == '\\') && (i+1 < input_len) {
			c := -1

			switch input[i+1] {
			case 'a':
				c = '\a'
				break
			case 'b':
				c = '\b'
				break
			case 'f':
				c = '\f'
				break
			case 'n':
				c = '\n'
				break
			case 'r':
				c = '\r'
				break
			case 't':
				c = '\t'
				break
			case 'v':
				c = '\v'
				break
			case '\\':
				c = '\\'
				break
			case '?':
				c = '?'
				break
			case '\'':
				c = '\''
				break
			case '"':
				c = '"'
				break
			}

			if c != -1 {
				i += 2
			}

			/* Hexadecimal or octal? */
			if c == -1 {
				if (input[i+1] == 'x') || (input[i+1] == 'X') {
					/* Hexadecimal. */
					if (i+3 < input_len) && (utils.IsXDigit(int(input[i+2]))) && (utils.IsXDigit(int(input[i+3]))) {
						/* Two digits. */
						c = int(utils.X2c(input[i+2:]))
						i += 4
					} else {
						/* Invalid encoding, do nothing. */
					}
				} else {
					if utils.IsODigit(input[i+1]) { /* Octal. */
						buf := make([]byte, 4)
						j := 0

						for (i+1+j < input_len) && (j < 3) {
							buf[j] = input[i+1+j]
							j++
							if (len(input) > (i + 1 + j)) && !utils.IsODigit(input[i+1+j]) {
								break
							}
						}
						//buf[j] = '\x00'
						//This line actually means that the string ends here so:
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
	return string(data[:count])
}
