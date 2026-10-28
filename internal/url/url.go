// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"strings"
)

// KeyValue holds a single parsed key-value pair in parse order.
type KeyValue struct {
	Key   string
	Value string
}

// ParseQueryOrdered parses the URL-encoded query string and returns key-value
// pairs in the order they appear in the input, plus whether parsing stopped
// early because limit was reached (limit <= 0 means no limit). Stopping the
// parse itself, rather than only capping what a caller later copies out of
// the result, matters because building the full result is what actually
// spends the memory: a query string with millions of pairs (repeated key or
// not) would otherwise allocate for every single one of them before any
// caller-side limit ever got a chance to run. See GHSA-3ww9-vw83-9w5x. limit
// counts total pairs parsed, not distinct keys, so it isn't fooled by many
// values crammed under one repeated key either.
// The order keeps rules deterministic: they see the arguments in the same
// order on every evaluation, and the same pairs survive the limit.
// It takes the separator as parameter, for example: & or ;
func ParseQueryOrdered(query string, separator byte, limit int) (result []KeyValue, truncated bool) {
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
			return result, true
		}
		value := ""
		if i := strings.IndexByte(key, '='); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		key = queryUnescape(key)
		value = queryUnescape(value)
		result = append(result, KeyValue{Key: key, Value: value})
	}
	return result, false
}

// queryUnescape is a non-strict version of net/url.QueryUnescape.
func queryUnescape(input string) string {
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
