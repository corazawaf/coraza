// Copyright 2022 Juan Pablo Tosso
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

import "strings"

func urlEncode(data string) (string, error) {
	return doURLEncode(data), nil
}

func doURLEncode(input string) string {
	inputLen := len(input)
	if inputLen == 0 {
		return ""
	}

	length := inputLen * 3
	var d strings.Builder
	d.Grow(length)
	c2xTable := []byte("0123456789abcdef")

	/* ENH Only encode the characters that really need to be encoded. */

	for i := 0; i < inputLen; i++ {
		cc := input[i]

		if cc == ' ' {
			d.WriteByte('+')
		} else {
			if (cc == 42) || ((cc >= 48) && (cc <= 57)) || ((cc >= 65) && (cc <= 90)) || ((cc >= 97) && (cc <= 122)) {
				d.WriteByte(cc)
			} else {
				d.Write([]byte{'%', c2xTable[(cc&0xff)>>4], c2xTable[(cc&0xff)&0x0f]})
			}
		}
	}

	return d.String()
}
