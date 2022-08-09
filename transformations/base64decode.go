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

var base64DecMap = []byte{
	127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	127, 127, 127, 62, 127, 127, 127, 63, 52, 53,
	54, 55, 56, 57, 58, 59, 60, 61, 127, 127,
	127, 64, 127, 127, 127, 0, 1, 2, 3, 4,
	5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	25, 127, 127, 127, 127, 127, 127, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
	39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
	49, 50, 51, 127, 127, 127, 127, 127,
}

// base64decode decodes a Base64-encoded string.
// Important: We cannot use the golang base64 package because it does not
// support mixed content like RAW+BASE64+RAW
// This implementations supports base64 between non-base64 content
func base64decode(data string) (string, error) {
	res := doBase64decode(data)
	if res == "" {
		return data, nil
	}
	return res, nil
}

func doBase64decode(src string) string {
	slen := len(src)
	if slen == 0 {
		return src
	}

	var j, x, i, n int

	/* First pass: check for validity and get output length */
	for ; i < slen; i++ {
		/* Skip spaces before checking for EOL */
		x = 0
		for i < slen && src[i] == ' ' {
			i++
			x++
		}

		/* Spaces at end of buffer are OK */
		if i == slen {
			break
		}

		if (slen-i) >= 2 && src[i] == '\r' && src[i+1] == '\n' {
			continue
		}

		if src[i] == '\n' {
			continue
		}

		/* Space inside a line is an error */
		if x != 0 {
			return src
		}
		if src[i] == '=' {
			j++
			if j > 2 {
				// ERROR
				return src
			}
		}

		if src[i] > 127 || base64DecMap[src[i]] == 127 {
			// ERROR
			return src
		}

		if base64DecMap[src[i]] < 64 && j != 0 {
			// ERROR
			return src
		}
		n++
	}

	n = ((n * 6) + 7) >> 3
	n -= j
	if slen < n {
		// ERROR
		return src
	}

	j = 3
	n = 0
	x = 0
	srcc := 0

	var dst strings.Builder
	dst.Grow(slen)

	for ; i > 0; i-- {
		if src[srcc] == '\r' || src[srcc] == '\n' || src[srcc] == ' ' {
			srcc++
			continue
		}
		if base64DecMap[src[srcc]] == 64 {
			j--
		}

		x = (x << 6) | int(base64DecMap[src[srcc]]&0x3F)
		n++
		if n == 4 {
			n = 0
			if j > 0 {
				dst.WriteByte(byte(x >> 16))
			}
			if j > 1 {
				dst.WriteByte(byte(x >> 8))
			}
			if j > 2 {
				dst.WriteByte(byte(x))
			}
		}
		srcc++
	}

	return dst.String()
}
