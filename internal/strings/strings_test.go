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

func TestHasRegex(t *testing.T) {
	tCases := []struct {
		name          string
		input         string
		expectIsRegex bool
		expectPattern string
	}{
		{
			name:          "valid regex pattern",
			input:         "/user/",
			expectIsRegex: true,
			expectPattern: "user",
		},
		{
			name:          "escaped slash at end — not a regex",
			input:         `/user\/`,
			expectIsRegex: false,
			expectPattern: `/user\/`,
		},
		{
			name:          "double-escaped slash at end — is a regex",
			input:         `/user\\/`,
			expectIsRegex: true,
			expectPattern: `user\\`,
		},
		{
			name:          "triple-escaped slash at end — not a regex",
			input:         `/user\\\/`,
			expectIsRegex: false,
			expectPattern: `/user\\\/`,
		},
		{
			name:          "empty pattern //",
			input:         "//",
			expectIsRegex: true,
			expectPattern: "",
		},
		{
			name:          "too short — single char",
			input:         "/",
			expectIsRegex: false,
			expectPattern: "/",
		},
		{
			name:          "no leading slash",
			input:         "user/",
			expectIsRegex: false,
			expectPattern: "user/",
		},
		{
			name:          "no trailing slash",
			input:         "/user",
			expectIsRegex: false,
			expectPattern: "/user",
		},
		{
			name:          "complex pattern with anchors and quantifiers",
			input:         `/^json\.\d+\.field$/`,
			expectIsRegex: true,
			expectPattern: `^json\.\d+\.field$`,
		},
		{
			name:          "pattern with character class",
			input:         "/user[0-9]+/",
			expectIsRegex: true,
			expectPattern: "user[0-9]+",
		},
		{
			name:          "plain string without slashes",
			input:         "username",
			expectIsRegex: false,
			expectPattern: "username",
		},
		{
			name:          "empty string",
			input:         "",
			expectIsRegex: false,
			expectPattern: "",
		},
	}

	for _, tCase := range tCases {
		t.Run(tCase.name, func(t *testing.T) {
			gotIsRegex, gotPattern := HasRegex(tCase.input)
			if gotIsRegex != tCase.expectIsRegex {
				t.Errorf("HasRegex(%q): isRegex = %v, want %v", tCase.input, gotIsRegex, tCase.expectIsRegex)
			}
			if gotPattern != tCase.expectPattern {
				t.Errorf("HasRegex(%q): pattern = %q, want %q", tCase.input, gotPattern, tCase.expectPattern)
			}
		})
	}
}
