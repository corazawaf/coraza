// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strconv"
	"strings"

	utils "github.com/corazawaf/coraza/v3/internal/strings"
)

func escapeSeqDecode(input string) (string, bool, error) {
	if i := strings.IndexByte(input, '\\'); i != -1 {
		// TODO: This will transform even if the backslash isn't followed by an escape,
		// but keep it simple for now.
		transformedInput, changed := doEscapeSeqDecode(input, i)
		return transformedInput, changed, nil
	}
	return input, false, nil
}

func doEscapeSeqDecode(input string, pos int) (string, bool) {
	inputLen := len(input)
	data := []byte(input)
	changed := false
	d := pos
	i := pos

	for i < inputLen {
		if (input[i] == '\\') && (i+1 < inputLen) {
			var c byte
			var ok bool

			switch input[i+1] {
			case 'a':
				c = '\a'
				ok = true
			case 'b':
				c = '\b'
				ok = true
			case 'f':
				c = '\f'
				ok = true
			case 'n':
				c = '\n'
				ok = true
			case 'r':
				c = '\r'
				ok = true
			case 't':
				c = '\t'
				ok = true
			case 'v':
				c = '\v'
				ok = true
			case '\\':
				c = '\\'
				ok = true
			case '?':
				c = '?'
				ok = true
			case '\'':
				c = '\''
				ok = true
			case '"':
				c = '"'
				ok = true
			}

			if ok {
				data[d] = c
				d += 1
				i += 2
				changed = true
				continue
			}

			/* Hexadecimal or octal? */
			if (input[i+1] == 'x' || input[i+1] == 'X') && i+3 < inputLen && utils.ValidHex(input[i+2]) && utils.ValidHex(input[i+3]) {
				/* Two digits. */
				data[d] = utils.X2c(input[i+2:])
				d += 1
				i += 4
				changed = true
				continue
			}

			if isODigit(input[i+1]) { /* Octal. */
				j := 2
				for j < 4 && i+j < inputLen && isODigit(input[i+j]) {
					j += 1
				}

				bc, _ := strconv.ParseUint(input[i+1:i+j], 8, 8)
				data[d] = byte(bc)
				d += 1
				i += j
				changed = true
				continue
			}

			/* Didn't recognise encoding, copy raw bytes. */
			data[d] = input[i+1]
			d++
			i += 2
		} else {
			/* Input character not a backslash, copy it. */
			data[d] = input[i]
			d++
			i++
		}
	}
	return utils.WrapUnsafe(data[:d]), changed
}

func isODigit(c byte) bool {
	return (c >= '0') && (c <= '7')
}
