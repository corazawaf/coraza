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

func TestRandomStringConcurrency(t *testing.T) {
	// Make sure random strings don't crash under high concurrency.
	for range 5000 {
		go RandomString(10000)
	}
}

func TestHasRegex(t *testing.T) {
	tCases := []struct {
		name           string
		input          string
		expectIsRegex  bool
		expectPattern  string
	}{
		{
			name:           "valid regex pattern",
			input:          "/user/",
			expectIsRegex:  true,
			expectPattern:  "user",
		},
		{
			name:           "escaped slash at end",
			input:          `/user\/`,
			expectIsRegex:  false,
			expectPattern:  `/user\/`,
		},
		{
			name:           "double escaped slash at end",
			input:          `/user\\/`,
			expectIsRegex:  true,
			expectPattern:  `user\\`,
		},
		{
			name:           "triple escaped slash at end",
			input:          `/user\\\/`,
			expectIsRegex:  false,
			expectPattern:  `/user\\\/`,
		},
		{
			name:           "empty pattern",
			input:          "//",
			expectIsRegex:  true,
			expectPattern:  "",
		},
		{
			name:           "too short",
			input:          "/a",
			expectIsRegex:  false,
			expectPattern:  "/a",
		},
		{
			name:           "no leading slash",
			input:          "user/",
			expectIsRegex:  false,
			expectPattern:  "user/",
		},
		{
			name:           "no trailing slash",
			input:          "/user",
			expectIsRegex:  false,
			expectPattern:  "/user",
		},
		{
			name:           "just slashes",
			input:          "//",
			expectIsRegex:  true,
			expectPattern:  "",
		},
	}

	for _, tCase := range tCases {
		t.Run(tCase.name, func(t *testing.T) {
			gotIsRegex, gotPattern := HasRegex(tCase.input)
			if gotIsRegex != tCase.expectIsRegex {
				t.Errorf("HasRegex(%q) isRegex = %v, want %v", tCase.input, gotIsRegex, tCase.expectIsRegex)
			}
			if gotPattern != tCase.expectPattern {
				t.Errorf("HasRegex(%q) pattern = %q, want %q", tCase.input, gotPattern, tCase.expectPattern)
			}
		})
	}
}
