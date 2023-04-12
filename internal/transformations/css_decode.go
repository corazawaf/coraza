// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strings"

	utils "github.com/corazawaf/coraza/v3/internal/strings"
)

func cssDecode(data string) (string, error) {
	if i := strings.IndexByte(data, '\\'); i != -1 {
		// TODO: This will transform even if the backslash isn't followed by hex,
		// but keep it simple for now.
		return cssDecodeInplace(data, i), nil
	}
	return data, nil
}

func cssDecodeInplace(input string, pos int) string {
	d := []byte(input)
	inputLen := len(d)
	i := pos
	c := pos

	for i < inputLen {
		/* Is the character a backslash? */
		if input[i] == '\\' {
			/* Is there at least one more byte? */
			if i+1 < inputLen {
				i++ /* We are not going to need the backslash. */

				/* Check for 1-6 hex characters following the backslash */
				j := 0
				for (j < 6) && (i+j < inputLen) && (utils.ValidHex(input[i+j])) {
					j++
				}

				switch {
				case j > 0:
					/* We have at least one valid hexadecimal character. */
					fullcheck := false

					/* For now just use the last two bytes. */
					switch j {
					/* Number of hex characters */
					case 1:
						d[c] = xsingle2c(input[i])
						c++

					case 2, 3:
						/* Use the last two from the end. */
						d[c] = utils.X2c(input[i+j-2:])
						c++
					case 4:
						/* Use the last two from the end, but request
						 * a full width check.
						 */
						d[c] = utils.X2c(input[i+j-2:])
						fullcheck = true

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
					}

					/* Full width ASCII (0xff01 - 0xff5e) needs 0x20 added */
					if fullcheck {
						if (d[c] > 0x00) && (d[c] < 0x5f) && ((input[i+j-3] == 'f') || (input[i+j-3] == 'F')) && ((input[i+j-4] == 'f') || (input[i+j-4] == 'F')) {
							d[c] += 0x20
						}

						c++
					}

					/* We must ignore a single whitespace after a hex escape */
					if (i+j < inputLen) && isspace(input[i+j]) {
						j++
					}

					/* Move over. */
					i += j
				case input[i] == '\n':
					/* No hexadecimal digits after backslash */
					/* A newline character following backslash is ignored. */
					i++
				default:
					/* The character after backslash is not a hexadecimal digit,
					 * nor a newline. */
					/* Use one character after backslash as is. */
					d[c] = input[i]
					i++
					c++
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
		}
	}

	/* Terminate output string. */
	d = d[:c]

	return utils.WrapUnsafe(d)
}

/**
 * Converts a single hexadecimal digit into a decimal value.
 */
func xsingle2c(what byte) byte {
	var digit byte
	if what >= 'A' {
		digit = ((what & 0xdf) - 'A') + 10
	} else {
		digit = what - '0'
	}
	return digit
}

func isspace(char byte) bool {
	//https://en.cppreference.com/w/cpp/string/byte/isspace
	return char == ' ' || char == '\f' || char == '\n' || char == '\t' || char == '\r' || char == '\v'
}
