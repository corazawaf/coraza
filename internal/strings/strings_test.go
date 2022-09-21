// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package strings

import "testing"

func TestMaybeUnquote(t *testing.T) {
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
			want:  `hello 'world`,
		},
		{
			input: `"hello 'world"`,
			want:  `hello 'world`,
		},
		{
			input: `"hello \"world"`,
			want:  `hello "world`,
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
			input: `"\u30cf\u30ed\u30fc world"`,
			want:  `ハロー world`,
		},
		{
			input: `"\s\x5c\x5c.*"`,
			want:  `\s\\.*`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := MaybeUnquote(tt.input); got != tt.want {
				t.Errorf("MaybeUnquote() = %s, want %s", got, tt.want)
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
