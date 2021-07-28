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
	"github.com/jptosso/coraza-waf/utils"
)

func UrlDecode(data string, utils *Tools) string {
	res, _, _ := doUrlDecode(data)
	return res
}

//extracted from https://github.com/senghoo/modsecurity-go/blob/master/utils/urlencode.go
func doUrlDecode(input string) (string, bool, int) {
	d := []byte(input)
	input_len := len(d)
	var i, count, invalid_count, c int

	changed := false

	for i < input_len {
		if input[i] == '%' {
			/* Character is a percent sign. */

			/* Are there enough bytes available? */
			if i+2 < input_len {
				c1 := input[i+1]
				c2 := input[i+2]
				if utils.ValidHex(c1) && utils.ValidHex(c2) {
					uni := utils.X2c(input[i+1:])

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
					invalid_count++
				}
			} else {
				/* Not enough bytes available, copy the raw bytes. */
				d[c] = input[i]
				c++
				i++
				count++
				invalid_count++
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

	return string(d[0:c]), changed, invalid_count

}
