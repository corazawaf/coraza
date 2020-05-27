package transformations

import (
	"regexp"
	"strconv"
)

func UrlDecodeUni(data string) string {
	//no funciona, ver https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/actions/transformations/url_decode_uni.cc
	return UrlDecode(decodeUnicodeEscapedChars(data))
}

func decodeUnicodeEscapedChars(s string) string {
	re := regexp.MustCompile(`%u[0-9ABCDEF]{4}`)
	return re.ReplaceAllStringFunc(s, func(s string) string {
		t, err := strconv.Unquote("\"" + `\u` + s[2:] + "\"")
		if err != nil {
			panic(err)
		}
		return t
	})
}
