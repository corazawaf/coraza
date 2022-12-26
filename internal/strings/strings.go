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
