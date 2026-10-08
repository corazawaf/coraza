// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"errors"
	"strings"
)

// ErrInvalidURLEncoding is returned when a query contains malformed percent encoding.
var ErrInvalidURLEncoding = errors.New("invalid URL encoding")

// KeyValue holds a single parsed key-value pair in parse order.
type KeyValue struct {
	Key   string
	Value string
}

// ParseQuery parses the URL-encoded query string and returns the corresponding
// map, whether parsing stopped early because limit was reached (limit <= 0
// means no limit), and whether any percent-encoding was malformed. Stopping
// the parse itself, rather than only capping what a caller later copies out of
// the result, matters because building the full map is what actually spends
// the memory: a query string with millions of pairs (repeated key or not)
// would otherwise allocate for every single one of them before any
// caller-side limit ever got a chance to run. See GHSA-3ww9-vw83-9w5x. limit
// counts total pairs parsed, not distinct keys, so it isn't fooled by many
// values crammed under one repeated key either.
// It takes separators as parameter, for example: & or ; or &;
// Parsing is non-strict: malformed percent encoding is kept as-is and
// ErrInvalidURLEncoding is returned alongside the fully populated result.
func ParseQuery(query string, separator byte, limit int) (result map[string][]string, truncated bool, err error) {
	return doParseQuery(query, separator, true, limit)
}

// ParseQueryOrdered parses the URL-encoded query string and returns key-value
// pairs in the order they appear in the input, whether parsing stopped early
// because limit was reached (limit <= 0 means no limit; see ParseQuery for why
// the parse itself, not just a later copy, is what needs to stop), and whether
// any percent-encoding was malformed. The order is important for deterministic
// behavior when an argument limit is enforced. Parsing is non-strict, as in
// ParseQuery.
func ParseQueryOrdered(query string, separator byte, limit int) (result []KeyValue, truncated bool, err error) {
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
		// Checked after the empty-key skip, right before a pair is actually
		// added: checking above it would report truncation for a trailing
		// separator once the limit was reached, even though nothing more was
		// going to be dropped (e.g. "a=1&b=2&&" with limit=2).
		if limit > 0 && len(result) >= limit {
			return result, true, err
		}
		value := ""
		if i := strings.IndexByte(key, '='); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		var keyErr, valueErr error
		key, keyErr = queryUnescape(key)
		value, valueErr = queryUnescape(value)
		if keyErr != nil || valueErr != nil {
			err = ErrInvalidURLEncoding
		}
		result = append(result, KeyValue{Key: key, Value: value})
	}
	return result, false, err
}

func doParseQuery(query string, separator byte, urlUnescape bool, limit int) (m map[string][]string, truncated bool, err error) {
	m = make(map[string][]string)
	total := 0
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
		// See the matching comment in ParseQueryOrdered: checked after the
		// empty-key skip so a trailing separator at the limit doesn't report
		// truncation for a pair that was never going to be added.
		if limit > 0 && total >= limit {
			return m, true, err
		}
		value := ""
		if i := strings.IndexByte(key, '='); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		if urlUnescape {
			var keyErr, valueErr error
			key, keyErr = queryUnescape(key)
			value, valueErr = queryUnescape(value)
			if keyErr != nil || valueErr != nil {
				err = ErrInvalidURLEncoding
			}
		}
		m[key] = append(m[key], value)
		total++
	}
	return m, false, err
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
