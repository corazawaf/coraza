// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package strings

import (
	"strings"
	"testing"
)

func TestMaybeRemoveQuotes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: ``,
			want:  ``,
		},
		{
			input: `"`,
			want:  `"`,
		},
		{
			input: `""`,
			want:  ``,
		},
		{
			input: `"hello world"`,
			want:  `hello world`,
		},
		{
			input: `'hello world'`,
			want:  `hello world`,
		},
		{
			input: `'hello "world'`,
			want:  `hello "world`,
		},
		{
			input: `'hello \'world'`,
			want:  `hello \'world`,
		},
		{
			input: `"hello 'world"`,
			want:  `hello 'world`,
		},
		{
			input: `"hello \"world"`,
			want:  `hello \"world`,
		},
		{
			input: `"hello world'`,
			want:  `"hello world'`,
		},
		{
			input: `"hello world`,
			want:  `"hello world`,
		},
		{
			input: `'hello world"`,
			want:  `'hello world"`,
		},
		{
			input: `'hello world`,
			want:  `'hello world`,
		},
		{
			input: `"\x{30cf}\x{30ed}\x{30fc} world"`,
			want:  `\x{30cf}\x{30ed}\x{30fc} world`,
		},
		{
			input: `"\s\x5c.*"`,
			want:  `\s\x5c.*`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := MaybeRemoveQuotes(tt.input); got != tt.want {
				t.Errorf("MaybeRemoveQuotes() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRandomStringConcurrency(t *testing.T) {
	// Make sure random strings don't crash under high concurrency.
	for i := 0; i < 5000; i++ {
		go RandomString(10000)
	}
}

func TestAsciiToLower(t *testing.T) {
	word := "HELLO WORLD"
	if want, have := "hello world", AsciiToLower(word); want != have {
		t.Errorf("Unexpected lowercase word, want %q, have %q", want, have)
	}
}

func BenchmarkAsciiVsUnicodeCaseString(b *testing.B) {
	strs := []string{
		"!!!!!!!!!!!!!!aaaaaaaaa please merge me!!!",
		"This is a String With a lot of Characters!!!",
		"this is a lowercase string with many characters",
		"THIS IS AN UPPERCASE STRING WITH MANY CHARACTERS",
		"ThIs Is A StRiNg WiTh MiXeD CaSe",
	}
	b.Run("hacky ascii", func(b *testing.B) {
		for _, str := range strs {
			b.Run(str, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					AsciiToLower(str)
				}
			})
		}
	})
	b.Run("standard ascii", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, s := range strs {
				bts := []byte(s)
				for i := 0; i < len(s); i++ {
					c := s[i]
					if c >= 'A' && c <= 'Z' {
						bts[i] = c + 32
					}
				}
				_ = string(bts)
			}
		}
	})
	b.Run("unicode", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, str := range strs {
				strings.ToLower(str)
			}
		}
	})
}
