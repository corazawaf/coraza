// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package strings

import (
	"math/rand"
	"strings"
	"sync"
	"time"
	"unsafe"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())
var mu sync.Mutex

// RandomString returns a pseudorandom string of length n.
// It is safe to use this function in concurrent environments.
// Implementation from https://stackoverflow.com/a/31832326
func RandomString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)

	mu.Lock()
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	mu.Unlock()

	return sb.String()
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

// HasRegex checks if a string is enclosed in forward slashes (e.g., "/pattern/")
// and handles escaped slashes properly. Returns true only if the string starts with '/'
// and ends with an unescaped '/'. If the string is a regex pattern, it also returns
// the pattern content (without the surrounding slashes).
func HasRegex(s string) (bool, string) {
	if len(s) < 2 || s[0] != '/' {
		return false, s
	}
	
	// Check if the last character is '/' and it's not escaped
	lastChar := len(s) - 1
	if s[lastChar] != '/' {
		return false, s
	}
	
	// For "//" we should return true even though it's empty
	if lastChar == 1 {
		return true, ""
	}
	
	// Count consecutive backslashes before the last '/'
	backslashCount := 0
	for i := lastChar - 1; i >= 0 && s[i] == '\\'; i-- {
		backslashCount++
	}
	
	// If there's an even number of backslashes (including 0), the '/' is not escaped
	// If there's an odd number, the '/' is escaped
	if backslashCount%2 == 0 {
		return true, s[1:lastChar]
	}
	
	return false, s
}
