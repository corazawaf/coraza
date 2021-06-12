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
	"fmt"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

const (
	UNICODE_ERROR_CHARACTERS_MISSING   = -1
	UNICODE_ERROR_INVALID_ENCODING     = -2
	UNICODE_ERROR_OVERLONG_CHARACTER   = -3
	UNICODE_ERROR_RESTRICTED_CHARACTER = -4
	UNICODE_ERROR_DECODING_ERROR       = -5
)

func Utf8ToUnicode(str string) string {
	if str == "" {
		return ""
	}
	input_len := len(str)
	length := input_len * 4 + 1
	bytes_left := input_len
	count := 0
	data := make([]byte, length)
	unicode := make([]byte, 8)
	datai := 0

	for i := 0; i < bytes_left; {
		unicode_len := 0
		utf := str[i:]
		c := utf[0]
		d := 0
		if (c & 0x80) == 0 {
			count++
			if count <= length {
				if c == 0 && input_len > i+1 {
					z := make([]byte, 2)
					z[0] = utf[0]
					z[1] = utf[1]
					data[datai] = utils.X2c(string(z))
				} else {
					data[datai] = c
					datai++
				}
			}
		} else if (c & 0xE0) == 0xC0 {
			/* If first byte begins with binary 110 it is two byte encoding*/
			/* check we have at least two bytes */
			if bytes_left < 2 {
				/* check second byte starts with binary 10 */
				unicode_len = UNICODE_ERROR_CHARACTERS_MISSING
			} else if (utf[1] & 0xC0) != 0x80 {
				unicode_len = UNICODE_ERROR_INVALID_ENCODING
			} else {
				unicode_len = 2
				count += 6
				if count <= length {
					l := 0
					/* compute character number */
					d = int(((c & 0x1F) << 6) | (utf[1] & 0x3F))
					data[datai] = '%'
					datai++
					data[datai] = 'u'
					datai++
					unicode = []byte(fmt.Sprintf("%x", d))
					l = len(unicode)

					switch l {
					case 1:
						data[datai] = '0'
						datai++
						data[datai] = '0'
						datai++
						data[datai] = '0'
						datai++
						break
					case 2:
						data[datai] = '0'
						datai++
						data[datai] = '0'
						datai++
						break
					case 3:
						data[datai] = '0'
						datai++
						break
					case 4:
					case 5:
						break
					}

					for j := 0; j < l; j++ {
						data[datai] = unicode[j]
						datai++
					}
				}
			}
		} else if (c & 0xF0) == 0xE0 {
			/* If first byte begins with binary 1110 it is three byte encoding */
			/* check we have at least three bytes */
			if bytes_left < 3 {
				/* check second byte starts with binary 10 */
				unicode_len = UNICODE_ERROR_CHARACTERS_MISSING
			} else if ((utf[1]) & 0xC0) != 0x80 {
				/* check third byte starts with binary 10 */
				unicode_len = UNICODE_ERROR_INVALID_ENCODING
			} else if ((utf[2]) & 0xC0) != 0x80 {
				unicode_len = UNICODE_ERROR_INVALID_ENCODING
			} else {
				unicode_len = 3
				count += 6
				if count <= length {
					l := 0
					/* compute character number */
					d = int(((c & 0x0F) << 12) | ((utf[1] & 0x3F) << 6) | (utf[2] & 0x3F))
					data[datai] = '%'
					datai++
					data[datai] = 'u'
					datai++
					unicode = []byte(fmt.Sprintf("%x", d))
					l = len(unicode)

					switch l {
					case 1:
						data[datai] = '0'
						datai++
						data[datai] = '0'
						datai++
						data[datai] = '0'
						datai++
						break
					case 2:
						data[datai] = '0'
						datai++
						data[datai] = '0'
						datai++
						break
					case 3:
						data[datai] = '0'
						datai++
					case 4:
					case 5:
						break
					}

					for j := 0; j < l; j++ {
						data[datai] = unicode[j]
						datai++
					}
				}
			}
		} else if (c & 0xF8) == 0xF0 {
			/* If first byte begins with binary 11110 it
			 * is four byte encoding
			 */
			/* restrict characters to UTF-8 range (U+0000 - U+10FFFF) */
			if c >= 0xF5 {
				data[datai] = c
				datai++
			}
			/* check we have at least four bytes */
			if bytes_left < 4 {
				/* check second byte starts with binary 10 */
				unicode_len = UNICODE_ERROR_CHARACTERS_MISSING
			} else if (iOrNull(utf, 1) & 0xC0) != 0x80 {
				/* check third byte starts with binary 10 */
				unicode_len = UNICODE_ERROR_INVALID_ENCODING
			} else if (iOrNull(utf, 2) & 0xC0) != 0x80 {
				/* check forth byte starts with binary 10 */
				unicode_len = UNICODE_ERROR_INVALID_ENCODING
			} else if (iOrNull(utf, 3) & 0xC0) != 0x80 {
				unicode_len = UNICODE_ERROR_INVALID_ENCODING
			} else {
				unicode_len = 4
				count += 7
				if count <= length {
					/* compute character number */
					d = int(((c & 0x07) << 18) | ((utf[1] & 0x3F) << 12) | ((utf[2] & 0x3F) << 6) | (utf[3] & 0x3F))
					data[datai] = '%'
					datai++
					data[datai] = 'u'
					datai++
					unicode = []byte(fmt.Sprintf("%x", d))
					l := len(unicode)

					switch l {
					case 1:
						data[datai] = '0'
						datai++
						data[datai] = '0'
						datai++
						data[datai] = '0'
						datai++
						break
					case 2:
						data[datai] = '0'
						datai++
						data[datai] = '0'
						datai++
						break
					case 3:
						data[datai] = '0'
						datai++
						break
					case 4:
					case 5:
						break
					}

					for j := 0; j < l; j++ {
						data[datai] = unicode[j]
						datai++
					}
				}
			}
		} else {
			count++
			if count <= length {
				data[datai] = c
				datai++
			}
		}
		if (d >= 0xD800) && (d <= 0xDFFF) {
			count++
			if count <= length {
				data[datai] = c
				datai++
			}
		}
		/* check for overlong */
		if (unicode_len == 4) && (d < 0x010000) {
			/* four byte could be represented with less bytes */
			count++
			if count <= length {
				data[datai] = c
				datai++
			}
		} else if (unicode_len == 3) && (d < 0x0800) {
			/* three byte could be represented with less bytes */
			count++
			if count <= length {
				data[datai] = c
				datai++
			}
		} else if (unicode_len == 2) && (d < 0x80) {
			/* two byte could be represented with less bytes */
			count++
			if count <= length {
				data[datai] = c
				datai++
			}
		}

		if unicode_len > 0 {
			i += unicode_len
		} else {
			i++
		}
	}
	return string(data[0:datai])
}

func iOrNull(b string, i int) byte {
	if len(b) <= i {
		return '\x00'
	}
	return b[i]
}