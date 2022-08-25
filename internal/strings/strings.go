// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package strings

import (
	"crypto/rand"
	"strings"
	"sync"
)

const (
	randomBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

var mu sync.Mutex

// SafeRandom returns a random string of length n
// It is safe to use this function in concurrent environments
// If it fails, it will try again, it should fail more than once
func SafeRandom(length int) string {
	bytes := make([]byte, length)
	// There is an entropy bug here with a lot of concurrency, so we need sync

	mu.Lock()
	_, err := rand.Read(bytes)
	mu.Unlock()
	if err != nil {
		// TODO is it ok?
		return SafeRandom(length)
	}

	for i, b := range bytes {
		bytes[i] = randomBytes[b%byte(len(randomBytes))]
	}
	return string(bytes)
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

// RemoveQuotes removes quotes from a string
func RemoveQuotes(s string) string {
	if s == "" {
		return ""
	}
	s = strings.Trim(s, `"`)
	s = strings.Trim(s, `'`)
	return s
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
