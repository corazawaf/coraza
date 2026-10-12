// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package strings

import (
	"math/rand/v2"
	"strings"
	"unsafe"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// RandomString returns a pseudorandom string of length n.
//
// It is safe to use in concurrent environments: math/rand/v2's top-level
// functions are goroutine-safe and lock-free, drawing from a per-P generator
// that is seeded randomly at startup.
//
// This used to hold a package-level sync.Mutex around a manually seeded
// rand.Source (added in #430, Sept 2022). That was the right fix at the time:
// on Go 1.19 the math/rand global source was guarded by an internal mutex and
// had to be seeded by hand, so sharing one Source across goroutines needed
// external synchronisation. Both reasons are gone -- Go 1.20 made the global
// source auto-seeded and lock-free, and Go 1.22 added math/rand/v2 -- and the
// mutex had become the bottleneck it was meant to make safe: RandomString is
// called once per transaction (see internal/corazawaf/waf.go), so under load
// every transaction contended on it and throughput got *worse* as cores were
// added. See BenchmarkRandomString.
func RandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.IntN(len(letterBytes))]
	}
	return string(b)
}

// ValidHex returns true if the byte is a valid hex character
func ValidHex(x byte) bool {
	return (x >= '0' && x <= '9') || (x >= 'a' && x <= 'f') || (x >= 'A' && x <= 'F')
}

// X2c converts a hex character to its ascii value
func X2c(what string) byte {
	var digit byte
	if what[0] >= 'A' {
		digit = ((what[0] & 0xdf) - 'A') + 10
	} else {
		digit = what[0] - '0'
	}
	digit *= 16
	if what[1] >= 'A' {
		digit += ((what[1] & 0xdf) - 'A') + 10
	} else {
		digit += what[1] - '0'
	}

	return digit
}

// MaybeRemoveQuotes removes the quotes from the string if it begins and ends with them.
func MaybeRemoveQuotes(s string) string {
	if len(s) < 2 {
		return s
	}

	switch s[0] {
	case '"':
		if s[len(s)-1] != '"' {
			return s
		}
	case '\'':
		if s[len(s)-1] != '\'' {
			return s
		}
	default:
		return s
	}

	return s[1 : len(s)-1]
}

// UnescapeQuotedString unescapes `\"` sequences to `"` in seclang quoted
// strings. This is the only escape sequence recognized by the seclang quoted
// string parser — backslashes before any other character (including other
// backslashes) are left as-is so that operator arguments like regex patterns
// are passed through unchanged.
func UnescapeQuotedString(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}

	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == '"' {
			sb.WriteByte('"')
			i++ // skip the quote
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// InSlice returns true if the string is in the slice
func InSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// WrapUnsafe wraps the provided buffer as a string. The buffer
// must not be mutated after calling this function.
func WrapUnsafe(buf []byte) string {
	return *(*string)(unsafe.Pointer(&buf))
}

// HasRegex checks if s is enclosed in unescaped forward slashes (e.g. "/pattern/"),
// consistent with the ModSecurity regex delimiter convention. It returns (true, pattern)
// where pattern is the content between the slashes. Escaped closing slashes (e.g. "/foo\/")
// are treated as plain strings and return (false, s).
func HasRegex(s string) (bool, string) {
	if len(s) < 2 || s[0] != '/' {
		return false, s
	}
	lastIdx := len(s) - 1
	if s[lastIdx] != '/' {
		return false, s
	}
	// "//" edge-case: empty pattern
	if lastIdx == 1 {
		return true, ""
	}
	// Count consecutive backslashes immediately before the closing '/'.
	// An even count (including zero) means the '/' is unescaped.
	backslashes := 0
	for i := lastIdx - 1; i >= 0 && s[i] == '\\'; i-- {
		backslashes++
	}
	if backslashes%2 == 0 {
		return true, s[1:lastIdx]
	}
	return false, s
}
