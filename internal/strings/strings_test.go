// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package strings

import (
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

func TestFastEqualFold(t *testing.T) {
	cases := []struct {
		a string
		b string
		c bool
	}{
		{"", "", true},
		{"a", "a", true},
		{"a", "A", true},
		{"A", "a", true},
		{"A", "A", true},
		{"aaAAAAAaaaaaa.__$!", "aaaaaaaaaaaaa.__$!", true},
		{"aA", "bb", false},
		{"aAA", "aa", false},
	}
	for _, c := range cases {
		if FastEqualFold(c.a, c.b) != c.c {
			t.Errorf("FastEqualFold(%s, %s) != %t", c.a, c.b, c.c)
		}
	}
}

func BenchmarkEqualFold(b *testing.B) {
	for i := 0; i < b.N; i++ {
		FastEqualFold("a", "A")
	}
}

func BenchmarkLowerFast(b *testing.B) {
	str := "aaabbb....,,,cccdddeFFFeeeGGGIIIlllOOOppppnnnaaa!!!"
	for i := 0; i < b.N; i++ {
		FastLower(str)
	}
}
