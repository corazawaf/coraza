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
	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/utils/strings"
)

func urlDecode(data string, utils coraza.RuleTransformationTools) string {
	res, _, _ := doURLDecode(data)
	return res
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
