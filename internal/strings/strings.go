// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package strings

import (
	"math/rand"
	"strconv"
	"strings"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

// RandomString returns a pseudorandom string of length n.
// It is safe to use this function in concurrent environments.
// Implementation from https://stackoverflow.com/a/31832326
func RandomString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
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

// MaybeUnquote unquotes a string if it is quoted, or returns it as-is if it isn't.
func MaybeUnquote(s string) string {
	if s == "" {
		return ""
	}
	// Single character cannot be a quoted string
	if len(s) == 1 {
		return s
	}

	var quote byte
	if s[0] == '"' {
		quote = '"'
	} else if s[0] == '\'' {
		quote = '\''
	}

	// Not a quoted string
	if quote == 0 {
		return s
	}

	// Unquote characters, passing through illegal escape sequences because seclang rules commonly use them to make
	// regex more readable.
	res := strings.Builder{}
	tail := s[1 : len(s)-1]
	for len(tail) > 0 {
		c, _, t, err := strconv.UnquoteChar(tail, quote)
		if err != nil {
			res.WriteByte(tail[0])
			tail = tail[1:]
		} else {
			res.WriteRune(c)
			tail = t
		}
	}

	return res.String()
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
