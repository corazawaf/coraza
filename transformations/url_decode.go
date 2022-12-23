// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"github.com/corazawaf/coraza/v3/internal/strings"
)

func urlDecode(data string) (string, error) {
	for i := 0; i < len(data); i++ {
		if data[i] == '%' || data[i] == '+' {
			// TODO add error?
			return doURLDecode(data, []byte(data), i), nil
		}
	}
	return data, nil
}

// extracted from https://github.com/senghoo/modsecurity-go/blob/master/utils/urlencode.go
func doURLDecode(input string, d []byte, pos int) string {
	inputLen := len(d)
	i := pos
	c := pos

	for i < inputLen {
		if input[i] == '%' {
			/* Character is a percent sign. */

			/* Are there enough bytes available? */
			if i+2 < inputLen {
				c1 := input[i+1]
				c2 := input[i+2]
				if strings.ValidHex(c1) && strings.ValidHex(c2) {
					uni := strings.X2c(input[i+1:])

					d[c] = uni
					c++
					i += 3
				} else {
					/* Not a valid encoding, skip this % */
					d[c] = input[i]
					c++
					i++
				}
			} else {
				/* Not enough bytes available, copy the raw bytes. */
				d[c] = input[i]
				c++
				i++
			}
		} else {
			/* Character is not a percent sign. */
			if input[i] == '+' {
				d[c] = ' '
				c++
			} else {
				d[c] = input[i]
				c++
			}
			i++
		}
	}

	return string(d[0:c])

}
