// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"strings"
)

// ParseQuery parses the URL-encoded query string and returns the corresponding map.
// It takes separators as parameter, for example: & or ; or &;
func ParseQuery(query string, separator byte) map[string][]string {
	return doParseQuery(query, separator, true)
}

// ParseQueryRaw splits a URL-encoded query string into key/value pairs
// WITHOUT percent-decoding, preserving the original wire-format encoding.
func ParseQueryRaw(query string, separator byte) map[string][]string {
	return doParseQuery(query, separator, false)
}

// ParseQueryBoth parses a URL-encoded query string in a single pass and returns
// both the decoded (cooked) and raw (non-decoded) key/value maps. This is more
// efficient than calling ParseQuery and ParseQueryRaw separately.
func ParseQueryBoth(query string, separator byte) (decoded, raw map[string][]string) {
	// Estimate pair count to pre-size maps and reduce rehashing.
	n := strings.Count(query, string(separator)) + 1
	decoded = make(map[string][]string, n)
	raw = make(map[string][]string, n)
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
		raw[key] = append(raw[key], value)
		dk := queryUnescape(key)
		decoded[dk] = append(decoded[dk], queryUnescape(value))
	}
	return decoded, raw
}

func doParseQuery(query string, separator byte, urlUnescape bool) map[string][]string {
	m := make(map[string][]string)
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
			key = queryUnescape(key)
			value = queryUnescape(value)
		}
		m[key] = append(m[key], value)
	}
	return m
}

// queryUnescape is a non-strict version of net/url.QueryUnescape.
func queryUnescape(input string) string {
	// Fast path: if no encoding characters are present, return input
	// without allocation. This is the common case for most parameter
	// names and many values.
	if strings.IndexByte(input, '%') < 0 && strings.IndexByte(input, '+') < 0 {
		return input
	}

	ilen := len(input)
	res := strings.Builder{}
	res.Grow(ilen)
	for i := 0; i < ilen; i++ {
		ci := input[i]
		if ci == '+' {
			res.WriteByte(' ')
			continue
		}
		if ci == '%' {
			if i+2 >= ilen {
				res.WriteByte(ci)
				continue
			}
			hi, ok := hexDigitToByte(input[i+1])
			if !ok {
				res.WriteByte(ci)
				continue
			}
			lo, ok := hexDigitToByte(input[i+2])
			if !ok {
				res.WriteByte(ci)
				continue
			}
			res.WriteByte(byte(hi<<4 | lo))
			i += 2
			continue
		}
		res.WriteByte(ci)
	}
	return res.String()
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
