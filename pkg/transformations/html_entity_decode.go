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
	"strconv"
	"strings"
	"unicode"

	"github.com/jptosso/coraza-waf/pkg/utils"
)

func HtmlEntityDecode(data string, utils *Tools) string {
	return doHtmlEntityDecode(data)
}

func doHtmlEntityDecode(input string) string {
	d := []byte(input)
	//d = append(d, 0x00)
	input_len := len(input)
	var i, count, curr int
	for (i < input_len) && (count < input_len) {
		cp := 1
		z := 1
		/* Require an ampersand and at least one character to
		 * start looking into the entity.
		 */
		if (input[i] == '&') && (i+1 < input_len) {
			k := i + 1
			j := i + 1
			if input[j] == '#' {
				/* Numerical entity. */
				cp++
				if !(j+1 < input_len) {
					goto HTML_ENT_OUT /* Not enough bytes. */
				}
				j++
				if (input[j] == 'x') || (input[j] == 'X') {
					/* Hexadecimal entity. */
					cp++
					if !(j+1 < input_len) {
						goto HTML_ENT_OUT /* Not enough bytes. */
					}
					j++ /* j is the position of the first digit now. */
					k = j
					for (j < input_len) && (utils.IsXDigit(int(input[j]))) {
						j++
					}
					if j > k { /* Do we have at least one digit? */
						/* Decode the entity. */
						x := input[k:j]
						n, _ := strconv.ParseInt(string(x), 16, 8)
						d[curr] = byte(n)
						curr++
						count++
						/* Skip over the semicolon if it's there. */
						if (j < input_len) && (input[j] == ';') {
							i = j + 1
						} else {
							i = j
						}
						continue
					} else {
						goto HTML_ENT_OUT
					}
				} else {
					/* Decimal entity. */
					k = j
					for (j < input_len) && (unicode.IsNumber(rune(input[j]))) {
						j++
					}
					if j > k { /* Do we have at least one digit? */
						/* Decode the entity. */
						x := input[k:j]
						n, _ := strconv.ParseInt(string(x), 10, 8)
						d[curr] = byte(n)
						curr++
						count++
						/* Skip over the semicolon if it's there. */
						if (j < input_len) && (input[j] == ';') {
							i = j + 1
						} else {
							i = j
						}
						continue
					} else {
						goto HTML_ENT_OUT
					}
				}
			} else {
				/* Text entity. */
				k = j
				for j < input_len && utils.IsAlnum(string(input[j])) {
					j++
				}
				if j > k { /* Do we have at least one digit? */
					x := input[k:j]
					/* Decode the entity. */
					/* ENH What about others? */
					if strings.EqualFold(string(x), "quot") {
						d[curr] = '"'
						curr++
					} else if strings.EqualFold(string(x), "amp") {
						d[curr] = '&'
						curr++
					} else if strings.EqualFold(string(x), "lt") {
						d[curr] = '<'
						curr++
					} else if strings.EqualFold(string(x), "gt") {
						d[curr] = '>'
						curr++
					} else if strings.EqualFold(string(x), "nbsp") {
						d[curr] = '\x41'
						curr++
					} else {
						/* We do no want to convert this entity,
						 * cp the raw data over. */
						cp = j - k + 1
						goto HTML_ENT_OUT
					}
					count++
					/* Skip over the semicolon if it's there. */
					if (j < input_len) && (input[j] == ';') {
						i = j + 1
					} else {
						i = j
					}
					continue
				}
			}
		}
	HTML_ENT_OUT:
		for z = 0; (z < cp) && (count < input_len); z++ {
			d[curr] = input[i]
			curr++
			i++
			count++
		}
	}
	//d = d[:curr]
	return string(d[:count])
}
