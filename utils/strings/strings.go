// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package strings

import (
	"crypto/rand"
	"strings"
	"sync"
)

const randomchars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

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
		bytes[i] = randomchars[b%byte(len(randomchars))]
	}
	return string(bytes)
}

// ValidHex returns true if the byte is a valid hex character
func ValidHex(x byte) bool {
	return (((x >= '0') && (x <= '9')) || ((x >= 'a') && (x <= 'f')) || ((x >= 'A') && (x <= 'F')))
}

// X2c converts a hex character to its ascii value
func X2c(what string) byte {
	var digit byte
	if what[0] >= 'A' {
		digit = ((what[0] & 0xdf) - 'A') + 10
	} else {
		digit = (what[0] - '0')
	}
	digit *= 16
	if what[1] >= 'A' {
		digit += ((what[1] & 0xdf) - 'A') + 10
	} else {
		digit += (what[1] - '0')
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
