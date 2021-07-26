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

package operators

import (
	"github.com/jptosso/coraza-waf/v1/engine"
)

const (
	UNICODE_ERROR_CHARACTERS_MISSING   = -1
	UNICODE_ERROR_INVALID_ENCODING     = -2
	UNICODE_ERROR_OVERLONG_CHARACTER   = -3
	UNICODE_ERROR_RESTRICTED_CHARACTER = -4
	UNICODE_ERROR_DECODING_ERROR       = -5
)

type ValidateUtf8Encoding struct{}

func (o *ValidateUtf8Encoding) Init(data string) {
}

func (o *ValidateUtf8Encoding) Evaluate(tx *engine.Transaction, value string) bool {
	//TODO https://golang.org/pkg/unicode/utf8/#ValidString should be enough but it fails (?)
	str_c := []byte(value)
	bytes_left := len(str_c)
	for i := 0; i < len(value); {
		rc := detectUtf8Character(str_c[i:], bytes_left)
		//We use switch in case we debug information
		switch rc {
		case UNICODE_ERROR_CHARACTERS_MISSING:
			return true
		case UNICODE_ERROR_INVALID_ENCODING:
			return true
		case UNICODE_ERROR_OVERLONG_CHARACTER:
			return true
		case UNICODE_ERROR_RESTRICTED_CHARACTER:
			return true
		case UNICODE_ERROR_DECODING_ERROR:
			return true
		}

		if rc <= 0 {
			return true
		}

		i += rc
		bytes_left -= rc
	}
	return false
}

func detectUtf8Character(p_read []byte, length int) int {
	var c byte
	var unicode_len, d int
	if len(p_read) == 0 {
		return UNICODE_ERROR_DECODING_ERROR
	}
	c = p_read[0]

	/* If first byte begins with binary 0 it is single byte encoding */
	if (c & 0x80) == 0 {
		/* single byte unicode (7 bit ASCII equivilent) has no validation */
		return 1
	} else if (c & 0xE0) == 0xC0 {
		/* If first byte begins with binary 110 it is two byte encoding*/
		/* check we have at least two bytes */
		if length < 2 {
			unicode_len = UNICODE_ERROR_CHARACTERS_MISSING
		} else if (p_read[1] & 0xC0) != 0x80 {
			/* check second byte starts with binary 10 */
			unicode_len = UNICODE_ERROR_INVALID_ENCODING
		} else {
			unicode_len = 2
			/* compute character number */
			d = int(((c & 0x1F) << 6) | (p_read[1] & 0x3F))
		}
	} else if (c & 0xF0) == 0xE0 {
		/* If first byte begins with binary 1110 it is three byte encoding */
		/* check we have at least three bytes */
		if length < 3 {
			unicode_len = UNICODE_ERROR_CHARACTERS_MISSING
		} else if (p_read[1] & 0xC0) != 0x80 {
			/* check second byte starts with binary 10 */
			unicode_len = UNICODE_ERROR_INVALID_ENCODING
		} else if (p_read[2] & 0xC0) != 0x80 {
			/* check third byte starts with binary 10 */
			unicode_len = UNICODE_ERROR_INVALID_ENCODING
		} else {
			unicode_len = 3
			/* compute character number */
			d = int(((c & 0x0F) << 12) | ((p_read[1] & 0x3F) << 6) | (p_read[2] & 0x3F))
		}
	} else if (c & 0xF8) == 0xF0 {
		/* If first byte begins with binary 11110 it is four byte encoding */
		/* restrict characters to UTF-8 range (U+0000 - U+10FFFF)*/
		if c >= 0xF5 {
			return UNICODE_ERROR_RESTRICTED_CHARACTER
		}
		/* check we have at least four bytes */
		if length < 4 {
			unicode_len = UNICODE_ERROR_CHARACTERS_MISSING
		} else if (p_read[1] & 0xC0) != 0x80 {
			unicode_len = UNICODE_ERROR_INVALID_ENCODING
		} else if (p_read[2] & 0xC0) != 0x80 {
			unicode_len = UNICODE_ERROR_INVALID_ENCODING
		} else if (p_read[3] & 0xC0) != 0x80 {
			unicode_len = UNICODE_ERROR_INVALID_ENCODING
		} else {
			unicode_len = 4
			/* compute character number */
			d = int(((c & 0x07) << 18) | ((p_read[1] & 0x3F) << 12) | ((p_read[2] & 0x3F) << 6) | (p_read[3] & 0x3F))
		}
	} else {
		/* any other first byte is invalid (RFC 3629) */
		return UNICODE_ERROR_INVALID_ENCODING
	}

	/* invalid UTF-8 character number range (RFC 3629) */
	if (d >= 0xD800) && (d <= 0xDFFF) {
		return UNICODE_ERROR_RESTRICTED_CHARACTER
	}

	/* check for overlong */
	if (unicode_len == 4) && (d < 0x010000) {
		/* four byte could be represented with less bytes */
		return UNICODE_ERROR_OVERLONG_CHARACTER
	} else if (unicode_len == 3) && (d < 0x0800) {
		/* three byte could be represented with less bytes */
		return UNICODE_ERROR_OVERLONG_CHARACTER
	} else if (unicode_len == 2) && (d < 0x80) {
		/* two byte could be represented with less bytes */
		return UNICODE_ERROR_OVERLONG_CHARACTER
	}

	return unicode_len
}
