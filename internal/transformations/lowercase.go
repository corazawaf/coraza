// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strings"
)

func lowerCase(data string) (string, bool, error) {
	// Fast path: check if any byte actually needs lowering.
	// For ASCII-dominated WAF data (URLs, headers, parameter names),
	// most strings are already lowercase, so we avoid allocating entirely.
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c >= 'A' && c <= 'Z' {
			// Found an uppercase ASCII byte — allocate and transform from here.
			return lowerFrom(data, i), true, nil
		}
		if c >= 0x80 {
			// Non-ASCII byte — fall back to strings.ToLower for full Unicode support.
			transformedData := strings.ToLower(data)
			return transformedData, data != transformedData, nil
		}
	}
	// All bytes are already lowercase ASCII (or the string is empty).
	return data, false, nil
}

// lowerFrom lowercases data starting from position i, where data[:i] is already lowercase ASCII.
func lowerFrom(data string, i int) string {
	var b strings.Builder
	b.Grow(len(data))
	b.WriteString(data[:i])
	for ; i < len(data); i++ {
		c := data[i]
		if c >= 'A' && c <= 'Z' {
			b.WriteByte(c + ('a' - 'A'))
		} else if c >= 0x80 {
			// Non-ASCII: fall back to strings.ToLower for the remainder.
			b.WriteString(strings.ToLower(data[i:]))
			return b.String()
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
