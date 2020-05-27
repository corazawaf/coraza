package transformations

import (
	"net/url"
)

func UrlDecode(data string) string {
	ndata, err := url.QueryUnescape(data)
	if err != nil {
		return data
	}
	return ndata
}

/*

//extracted from https://github.com/senghoo/modsecurity-go/blob/master/utils/urlencode.go
//string, is unicode
func decode(s string, uni bool) (string, int) {
	// Count %, check that they're well-formed.
	errCount := 0
	res := bytes.NewBuffer(nil)
	for i := 0; i < len(s); {
		switch {
		case s[i] == '%' && len(s) > i+2 && IsHex(s[i+1]) && IsHex(s[i+2]):
			res.WriteByte(UnHex(s[i+1])<<4 | UnHex(s[i+2]))
			i += 3
		case uni && s[i] == '%' && len(s) > i+5 && (s[i+1] == 'u' || s[i+1] == 'U') && IsHex(s[i+2]) && IsHex(s[i+3]) && IsHex(s[i+4]) && IsHex(s[i+5]):
			var v rune
			var runeTmp [utf8.UTFMax]byte
			c0 := rune(UnHex(s[i+2]))
			c1 := rune(UnHex(s[i+3]))
			c2 := rune(UnHex(s[i+4]))
			c3 := rune(UnHex(s[i+5]))
			v = c0<<4 | c1
			if v == 0xff {
				v = (c2<<4 | c3) + 0x20 // full width ascii offset
			} else {
				v = v<<4 | c2
				v = v<<4 | c3
			}
			n := utf8.EncodeRune(runeTmp[:], v)
			res.Write(runeTmp[:n])
			i += 6
		case s[i] == '%':
			res.WriteByte('%')
			errCount++
			i++
		case s[i] == '+':
			res.WriteByte(' ')
			i++
		default:
			res.WriteByte(s[i])
			i++
		}
	}

	return res.String(), errCount
}

func IsHex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}
	return false
}

func UnHex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}*/