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
	"strings"
	"unicode"
)

func IsSpace(char byte) bool {
	//https://en.cppreference.com/w/cpp/string/byte/isspace
	return char == ' ' || char == '\f' || char == '\n' || char == '\t' || char == '\r' || char == '\v'
}

func StripSpaces(str string) string {
	return strings.Replace(str, " ", "", -1)
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

func C2x(what byte, where []byte) []byte {
	c2xTable := []byte("0123456789abcdef")
	b := []byte(where)

	what = what & 0xff
	b[0] = c2xTable[what>>4]
	b[1] = c2xTable[what&0x0f]

	return b
}

func IsODigit(x byte) bool {
	return (x >= '0') && (x <= '7')
}

func IsAlnum(s string) bool {
	for _, r := range s {
		if !unicode.IsNumber(r) && !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}
