// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"errors"
	"strings"
)

// ErrInvalidURLEncoding is returned when a query contains malformed percent encoding.
var ErrInvalidURLEncoding = errors.New("invalid URL encoding")

// ParseQuery parses the URL-encoded query string and returns the corresponding map.
// It takes separators as parameter, for example: & or ; or &;.
// Parsing is non-strict: malformed percent encoding is kept as-is and
// ErrInvalidURLEncoding is returned alongside the fully populated map.
func ParseQuery(query string, separator byte) (map[string][]string, error) {
	return doParseQuery(query, separator, true)
}

func doParseQuery(query string, separator byte, urlUnescape bool) (map[string][]string, error) {
	m := make(map[string][]string)
	var err error
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
			var keyErr, valueErr error
			key, keyErr = queryUnescape(key)
			value, valueErr = queryUnescape(value)
			if err == nil {
				if keyErr != nil {
					err = keyErr
				} else {
					err = valueErr
				}
			}
		}
		m[key] = append(m[key], value)
	}
	return m, err
}

// queryUnescape is a non-strict version of net/url.QueryUnescape.
// Malformed percent sequences are written as-is and reported through
// ErrInvalidURLEncoding.
func queryUnescape(input string) (string, error) {
	ilen := len(input)
	res := strings.Builder{}
	res.Grow(ilen)
	var err error
	for i := 0; i < ilen; i++ {
		ci := input[i]
		if ci == '+' {
			res.WriteByte(' ')
			continue
		}
		if ci == '%' {
			if i+2 >= ilen {
				err = ErrInvalidURLEncoding
				res.WriteByte(ci)
				continue
			}
			hi, ok := hexDigitToByte(input[i+1])
			if !ok {
				err = ErrInvalidURLEncoding
				res.WriteByte(ci)
				continue
			}
			lo, ok := hexDigitToByte(input[i+2])
			if !ok {
				err = ErrInvalidURLEncoding
				res.WriteByte(ci)
				continue
			}
			res.WriteByte(byte(hi<<4 | lo))
			i += 2
			continue
		}
		res.WriteByte(ci)
	}
	return res.String(), err
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
