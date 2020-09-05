package transformations

import (
	"fmt"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

const(
	UNICODE_ERROR_CHARACTERS_MISSING    = -1
	UNICODE_ERROR_INVALID_ENCODING      = -2
	UNICODE_ERROR_OVERLONG_CHARACTER    = -3
	UNICODE_ERROR_RESTRICTED_CHARACTER  = -4
	UNICODE_ERROR_DECODING_ERROR        = -5
)
func Utf8ToUnicode(str string) string {
	return doUtf8ToUnicode(str)
}

func doUtf8ToUnicode(input string) string{
    count := 0;
    var i, leng, j, curr int
    input_len := len(input)
    bytes_left := input_len
    unicode := make([]byte, 8)

    /* RFC3629 states that UTF-8 are encoded using sequences of 1 to 4 octets. */
    /* Max size per character should fit in 4 bytes */
    leng = input_len * 4 + 1
    data := make([]byte, leng)

    for i = 0; i < bytes_left;  {
        unicode_len := 0
        d := 0
        var c byte
        utf := []byte(input[i:])

        c = utf[0]

        /* If first byte begins with binary 0 it is single byte encoding */
        if ((c & 0x80) == 0) {
            /* single byte unicode (7 bit ASCII equivilent) has no validation */
            count++
            if count <= leng {
                if c == 0 && input_len > i + 1 {
                    z := make([]byte, 2)
                    z[0] = utf[0]
                    z[1] = utf[1]
                    data[curr] = utils.X2c(string(z))
                } else {
                    data[curr] = c
                    curr++
                }
            }
        } else if ((c & 0xE0) == 0xC0) {
            /* If first byte begins with binary 110 it is two byte encoding*/
            /* check we have at least two bytes */
            if (bytes_left < 2) {
                /* check second byte starts with binary 10 */
                unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            } else if ((utf[1] & 0xC0) != 0x80) {
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else {
                unicode_len = 2
                count +=6
                if (count <= leng) {
                    length := 0;
                    /* compute character number */
                    d = int(((c & 0x1F) << 6) | (utf[1] & 0x3F))
                    data[curr] = '%'
                    curr++
                    data[curr] = 'u'
                    curr++
					unicode = []byte(fmt.Sprintf("%x", d))
                    length = len(unicode)

                    switch (length) {
                        case 1:
                            data[curr] = '0'
                            data[curr+1] = '0'
                            data[curr+2] = '0'
                            curr += 3
                            break;
                        case 2:
                            data[curr] = '0'
                            data[curr+1] = '0'
                            curr += 2
                            break;
                        case 3:
                            data[curr] = '0'
                            curr++
                            break;
                        case 4:
                        case 5:
                            break
                    }

                    for j = 0; j < length; j++ {
                        data[curr] = unicode[j]
                        curr++
                    }

                }
            }
        } else if ((c & 0xF0) == 0xE0) {
        /* If first byte begins with binary 1110 it is three byte encoding */
            /* check we have at least three bytes */
            if (bytes_left < 3) {
                /* check second byte starts with binary 10 */
                unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            } else if (((utf[1]) & 0xC0) != 0x80) {
                /* check third byte starts with binary 10 */
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else if (((utf[2]) & 0xC0) != 0x80) {
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else {
                unicode_len = 3;
                count +=6;
                if (count <= leng) {
                    length := 0
                    /* compute character number */
                    d = int(((c & 0x0F) << 12) | ((utf[1] & 0x3F) << 6)  | (utf[2] & 0x3F))
                    data[curr] = '%'
                    curr++
                    data[curr] = 'u'
                    curr++
					unicode = []byte(fmt.Sprintf("%x", d))
                    length = len(unicode)

                    switch (length)  {
                        case 1:
                            data[curr] = '0'
                            data[curr+1] = '0'
                            data[curr+2] = '0'
                            curr += 3
                            break;
                        case 2:
                            data[curr] = '0'
                            data[curr+1] = '0'
                            curr += 2
                            break;
                        case 3:
                            data[curr] = '0'
                            curr++
                            break;
                        case 4:
                        case 5:
                            break;
                    }

                    for j = 0; j < length; j++ {
                        data[curr] = unicode[j]
                        curr++
                    }

                }
            }
        } else if ((c & 0xF8) == 0xF0) {
            /* If first byte begins with binary 11110 it
             * is four byte encoding
             */
            /* restrict characters to UTF-8 range (U+0000 - U+10FFFF) */
            if (c >= 0xF5) {
            	data[curr] = c
            	curr++
            }
            /* check we have at least four bytes */
            if (bytes_left < 4) {
                /* check second byte starts with binary 10 */
                unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            } else if (((utf[1]) & 0xC0) != 0x80) {
                /* check third byte starts with binary 10 */
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else if (((utf[2]) & 0xC0) != 0x80) {
                /* check forth byte starts with binary 10 */
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else if ((utf[3] & 0xC0) != 0x80) {
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else {
                unicode_len = 4
                count +=7
                if (count <= leng) {
                    length := 0;
                    /* compute character number */
                    d = int(((c & 0x07) << 18) | ((utf[1] & 0x3F) << 12) | ((utf[2] & 0x3F) << 6) | (utf[3] & 0x3F))
                    data[curr] = '%'
                    curr++
                    data[curr] = 'u'
                    curr++
                    unicode = []byte(fmt.Sprintf("%x", d))
                    length = len(unicode)

                    switch (length)  {
                        case 1:
                            data[curr] = '0'
                            data[curr+1] = '0'
                            data[curr+2] = '0'
                            curr += 3
                            break;
                        case 2:
                            data[curr] = '0'
                            data[curr+1] = '0'
                            curr += 2
                            break;
                        case 3:
                            data[curr] = '0'
                            curr++
                            break;
                        case 4:
                        case 5:
                            break;
                    }

                    for j = 0; j < length; j++ {
                        data[curr] = unicode[j]
                        curr++
                    }

                }
            }
        } else {
            /* any other first byte is invalid (RFC 3629) */
            count++
            if count <= leng {
            	data[curr] = c
            	curr++
            }
        }

        /* invalid UTF-8 character number range (RFC 3629) */
        if ((d >= 0xD800) && (d <= 0xDFFF)) {
            count++
            if (count <= leng){
                data[curr] = c
                curr++
            }
        }

        /* check for overlong */
        if ((unicode_len == 4) && (d < 0x010000)) {
            /* four byte could be represented with less bytes */
            count++
            if (count <= leng){
                data[curr] = c
                curr++
            }
        } else if ((unicode_len == 3) && (d < 0x0800)) {
            /* three byte could be represented with less bytes */
            count++
            if (count <= leng){
                data[curr] = c
                curr++
            }
        } else if ((unicode_len == 2) && (d < 0x80)) {
            /* two byte could be represented with less bytes */
            count++
            if (count <= leng){
                data[curr] = c
                curr++
            }
        }

        if (unicode_len > 0) {
            i += unicode_len
        } else {
            i++
        }
    }

    return string(data[0:curr])
}