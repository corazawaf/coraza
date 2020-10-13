// Copyright 2020 Juan Pablo Tosso
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
)

func CssDecode(data string) string {
	return cssDecodeInplace(data)
}

func cssDecodeInplace(input string) string {
	//TODO the following shall be int64?
	var c, i, j, count int
	d := []byte(input)
	input_len := len(d)

	for i < input_len {
		/* Is the character a backslash? */
		if input[i] == '\\' {
			/* Is there at least one more byte? */
			if i+1 < input_len {
				i++ /* We are not going to need the backslash. */

				/* Check for 1-6 hex characters following the backslash */
				j = 0
				for (j < 6) && (i+j < input_len) && (utils.ValidHex(input[i+j])) {
					j++
				}

				if j > 0 {
					/* We have at least one valid hexadecimal character. */
					fullcheck := false

					/* For now just use the last two bytes. */
					switch j {
					/* Number of hex characters */
					case 1:
						d[c] = xsingle2c(input[i:])
						c++
						break

					case 2:
						/* Use the last two from the end. */
						d[c] = utils.X2c(input[i+j-2:])
						c++
						break
					case 3:
						/* Use the last two from the end. */
						d[c] = utils.X2c(input[i+j-2:])
						c++
						break
					case 4:
						/* Use the last two from the end, but request
						 * a full width check.
						 */
						d[c] = utils.X2c(input[i+j-2:])
						fullcheck = true
						break

					case 5:
						/* Use the last two from the end, but request
						 * a full width check if the number is greater
						 * or equal to 0xFFFF.
						 */
						d[c] = utils.X2c(input[i+j-2:])
						/* Do full check if first byte is 0 */
						if input[i] == '0' {
							fullcheck = true
						} else {
							c++
						}
						break

					case 6:
						/* Use the last two from the end, but request
						 * a full width check if the number is greater
						 * or equal to 0xFFFF.
						 */
						d[c] = utils.X2c(input[i+j-2:])

						/* Do full check if first/second bytes are 0 */
						if (input[i] == '0') && (input[i+1] == '0') {
							fullcheck = true
						} else {
							c++
						}
						break
					}

					/* Full width ASCII (0xff01 - 0xff5e) needs 0x20 added */
					if fullcheck {
						if (d[c] > 0x00) && (d[c] < 0x5f) && ((input[i+j-3] == 'f') || (input[i+j-3] == 'F')) && ((input[i+j-4] == 'f') || (input[i+j-4] == 'F')) {
							d[c] += 0x20
						}

						c++
					}

					/* We must ignore a single whitespace after a hex escape */
					if (i+j < input_len) && isspace(input[i+j]) {
						j++
					}

					/* Move over. */
					count++
					i += j
				} else if input[i] == '\n' {
					/* No hexadecimal digits after backslash */
					/* A newline character following backslash is ignored. */
					i++
				} else {
					/* The character after backslash is not a hexadecimal digit,
					 * nor a newline. */
					/* Use one character after backslash as is. */
					d[c] = input[i]
					i++
					c++
					count++
				}
			} else {
				/* No characters after backslash. */
				/* Do not include backslash in output
				 *(continuation to nothing) */
				i++
			}
		} else {
			/* Character is not a backslash. */
			/* Copy one normal character to output. */
			d[c] = input[i]
			c++
			i++
			count++
		}
	}

	/* Terminate output string. */
	d = d[:c]

	return string(d)
}

/**
 * Converts a single hexadecimal digit into a decimal value.
 */
func xsingle2c(what string) byte {
	var digit byte
	if what[0] >= 'A' {
		digit = ((what[0] & 0xdf) - 'A') + 10
	} else {
		digit = what[0] - '0'
	}
	return digit
}

func isspace(char byte) bool {
	//https://en.cppreference.com/w/cpp/string/byte/isspace
	return char == ' ' || char == '\f' || char == '\n' || char == '\t' || char == '\r' || char == '\v'
}
