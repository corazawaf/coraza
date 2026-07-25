// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strings"
	"unicode/utf8"

	utils "github.com/corazawaf/coraza/v3/internal/strings"
)

func cssDecode(data string) (string, bool, error) {
	if i := strings.IndexByte(data, '\\'); i != -1 {
		// TODO: This will transform even if the backslash isn't followed by hex,
		// but keep it simple for now.
		return cssDecodeInplace(data, i), true, nil
	}
	return data, false, nil
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
					/* We have at least one valid hexadecimal character.
					 * Resolve the full code point (per the CSS Syntax spec,
					 * a hex escape always represents one code point, however
					 * many digits it takes to write it) and encode it as
					 * UTF-8 -- not a single truncated byte, which would
					 * produce invalid UTF-8 for any non-ASCII target and
					 * silently mis-decode 3+ digit escapes whose value
					 * doesn't fit in the last two digits alone. */
					var code rune
					for k := 0; k < j; k++ {
						code = code<<4 | rune(xsingle2c(input[i+k]))
					}

					/* Full width ASCII (U+FF01 - U+FF5E) folds to plain
					 * ASCII ('!' - '~'), matching ModSecurity's best-fit
					 * behavior for this transform. */
					if (code >= 0xff01) && (code <= 0xff5e) {
						code -= 0xfee0
					}

					c += utf8.EncodeRune(d[c:], code)

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
