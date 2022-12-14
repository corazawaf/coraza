// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"github.com/corazawaf/coraza/v3/internal/strings"
)

func urlDecode(data string) (string, error) {
	res, _, _ := doURLDecode(data)
	// TODO add error?
	return res, nil
}

// extracted from https://github.com/senghoo/modsecurity-go/blob/master/utils/urlencode.go
func doURLDecode(input string) (string, bool, int) {
	d := []byte(input)
	inputLen := len(d)
	var i, count, invalidCount, c int

	changed := false

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
					count++
					i += 3
					changed = true
				} else {
					/* Not a valid encoding, skip this % */
					d[c] = input[i]
					c++
					i++
					count++
					invalidCount++
				}
			} else {
				/* Not enough bytes available, copy the raw bytes. */
				d[c] = input[i]
				c++
				i++
				count++
				invalidCount++
			}
		} else {
			/* Character is not a percent sign. */
			if input[i] == '+' {
				d[c] = ' '
				c++
				changed = true
			} else {
				d[c] = input[i]
				c++
			}
			count++
			i++
		}
	}

	return string(d[0:c]), changed, invalidCount

}
