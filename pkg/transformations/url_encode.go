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

import ()

func UrlEncode(data string) string {
	return doUrlEncode(data)
}

func doUrlEncode(input string) string {
	input_len := len(input)
	var i, count, c int
	leng := input_len * 3
	d := make([]byte, leng)
	d = append(d, []byte(input)...)
	c2xTable := []byte("0123456789abcdef")

	/* ENH Only encode the characters that really need to be encoded. */

	for i = 0; i < input_len; i++ {
		cc := input[i]

		if cc == ' ' {
			d[c] = '+'
			c++
			count++
		} else {
			if (cc == 42) || ((cc >= 48) && (cc <= 57)) || ((cc >= 65) && (cc <= 90)) || ((cc >= 97) && (cc <= 122)) {
				d[c] = cc
				c++
				count++
			} else {
				d[c] = '%'
				c++
				count++
				d[c] = c2xTable[(cc&0xff)>>4]
				d[c+1] = c2xTable[(cc&0xff)&0x0f]
				c += 2
				count++
				count++
			}
		}
	}

	return string(d[0:count])
}
