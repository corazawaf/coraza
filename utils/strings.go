// Copyright 2021 Juan Pablo Tosso
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

package utils

import (
	"crypto/rand"
	"strings"
	"sync"
	"unicode"
)

const randomchars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var mu sync.Mutex

func RandomString(length int) string {
	bytes := make([]byte, length)
	// There is an entropy bug here with a lot of concurrency, so we need sync

	mu.Lock()
	_, err := rand.Read(bytes)
	mu.Unlock()
	if err != nil {
		// TODO is it ok?
		return RandomString(length)
	}

	for i, b := range bytes {
		bytes[i] = randomchars[b%byte(len(randomchars))]
	}
	return string(bytes)
}

func IsSpace(char byte) bool {
	//https://en.cppreference.com/w/cpp/string/byte/isspace
	return unicode.IsSpace(rune(char))
}

func ValidHex(x byte) bool {
	return (((x >= '0') && (x <= '9')) || ((x >= 'a') && (x <= 'f')) || ((x >= 'A') && (x <= 'F')))
}

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

func IsXDigit(char int) bool {
	c := byte(char)
	return ValidHex(c)
}

func IsODigit(x byte) bool {
	return (x >= '0') && (x <= '7')
}

func IsDigit(x byte) bool {
	return (x >= '0') && (x <= '9')
}

func TrimLeftChars(s string, n int) string {
	m := 0
	for i := range s {
		if m >= n {
			return s[i:]
		}
		m++
	}
	return s[:0]
}

func RemoveQuotes(s string) string {
	if s == "" {
		return ""
	}
	s = strings.Trim(s, `"`)
	s = strings.Trim(s, `'`)
	return s
}
