// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"strings"
)

// ParseQuery parses the URL-encoded query string and returns the corresponding map.
// The boolean is true when the query contains malformed percent encoding.
// It takes separators as parameter, for example: & or ; or &;.
func ParseQuery(query string, separator byte) (map[string][]string, bool) {
	return doParseQuery(query, separator, true)
}

func doParseQuery(query string, separator byte, urlUnescape bool) (map[string][]string, bool) {
	m := make(map[string][]string)
	var urlencodedError bool
	for query != "" {
		key := query
		if i := strings.IndexByte(key, separator); i >= 0 {
			key, query = key[:i], key[i+1:]
		} else {
			query = ""
		}
		if key == "" {
			continue
		}
		value := ""
		if i := strings.IndexByte(key, '='); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		if urlUnescape {
			var keyError, valueError bool
			key, keyError = queryUnescape(key)
			value, valueError = queryUnescape(value)
			urlencodedError = urlencodedError || keyError || valueError
		}
		m[key] = append(m[key], value)
	}
	return m, urlencodedError
}

// queryUnescape is a non-strict version of net/url.QueryUnescape.
// The boolean is true when the input contains malformed percent encoding.
func queryUnescape(input string) (string, bool) {
	ilen := len(input)
	res := strings.Builder{}
	res.Grow(ilen)
	var urlencodedError bool
	for i := 0; i < ilen; i++ {
		ci := input[i]
		if ci == '+' {
			res.WriteByte(' ')
			continue
		}
		if ci == '%' {
			if i+2 >= ilen {
				urlencodedError = true
				res.WriteByte(ci)
				continue
			}
			hi, ok := hexDigitToByte(input[i+1])
			if !ok {
				urlencodedError = true
				res.WriteByte(ci)
				continue
			}
			lo, ok := hexDigitToByte(input[i+2])
			if !ok {
				urlencodedError = true
				res.WriteByte(ci)
				continue
			}
			res.WriteByte(byte(hi<<4 | lo))
			i += 2
			continue
		}
		res.WriteByte(ci)
	}
	return res.String(), urlencodedError
}

func hexDigitToByte(digit byte) (byte, bool) {
	switch {
	case digit >= '0' && digit <= '9':
		return digit - '0', true
	case digit >= 'a' && digit <= 'f':
		return digit - 'a' + 10, true
	case digit >= 'A' && digit <= 'F':
		return digit - 'A' + 10, true
	default:
		return 0, false
	}
}
