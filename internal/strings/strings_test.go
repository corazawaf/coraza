// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package strings

import "testing"

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

func TestUnescapeQuotedString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: ``, want: ``},
		{input: `hello`, want: `hello`},
		{input: `\"`, want: `"`},
		{input: `\\`, want: `\\`},
		{input: `@contains \"`, want: `@contains "`},
		{input: `@rx C:\\`, want: `@rx C:\\`},
		{input: `hello \"world\"`, want: `hello "world"`},
		{input: `\n`, want: `\n`},
		{input: `no escapes here`, want: `no escapes here`},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := UnescapeQuotedString(tt.input); got != tt.want {
				t.Errorf("UnescapeQuotedString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRandomStringConcurrency(t *testing.T) {
	// Make sure random strings don't crash under high concurrency.
	for range 5000 {
		go RandomString(10000)
	}
}
