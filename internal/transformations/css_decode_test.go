// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestCSSDecode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: "Test\u0000Case",
			want:  "Test\u0000Case",
		},
		{
			input: "test\\a\\b\\f\\n\\r\\t\\v\\?\\'\\\"\\\u0000\\12\\123\\1234\\12345\\123456\\ff01\\ff5e\\\n\\\u0000  string",
			want:  "test\n\u000b\u000fnrtv?'\"\u0000\u0012\u0123\u1234\U00012345\uFFFD!~\u0000  string",
		},
		// A hex escape always resolves to one full Unicode code point (CSS
		// Syntax spec), UTF-8 encoded -- not a single truncated byte, which
		// produces invalid UTF-8 for any non-ASCII target. See
		// https://github.com/corazawaf/coraza/issues/1654.
		{
			input: "caf\\e9",
			want:  "caf\u00e9",
		},
		{
			// 3+ hex digits: the resolved value doesn't fit in the escape's
			// last two digits alone, so truncating to them (the old
			// behavior) silently decoded to the wrong character.
			input: "\\123",
			want:  "\u0123",
		},
		{
			// Supplementary-plane code point (4-byte UTF-8).
			input: "\\12345",
			want:  "\U00012345",
		},
		{
			// Value exceeds the max code point (0x10FFFF): resolves to the
			// Unicode replacement character, matching a spec-compliant
			// parser's handling of an invalid escaped code point.
			input: "\\123456",
			want:  "\uFFFD",
		},
		// A zero-value escaped code point is also invalid per the CSS
		// Syntax spec and must resolve to U+FFFD, not a literal NUL byte.
		// This also regression-tests the in-place buffer: "\0" is 2 input
		// bytes but U+FFFD is 3 output bytes, which panicked before the
		// decoder switched to a growable buffer. Found by CodeRabbit
		// review.
		{
			input: "\\0",
			want:  "\uFFFD",
		},
		{
			input: "\\000000",
			want:  "\uFFFD",
		},
		// A backslash before any CSS newline is a line continuation that
		// produces nothing, so "aler\<newline>t(1)" has to fold back into
		// "alert(1)" before a rule ever gets to look at it.
		{
			input: "aler\\\r\nt(1)",
			want:  "alert(1)",
		},
		{
			input: "aler\\\rt(1)",
			want:  "alert(1)",
		},
		{
			input: "aler\\\ft(1)",
			want:  "alert(1)",
		},
		{
			input: "aler\\\nt(1)",
			want:  "alert(1)",
		},
		// A CR or FF that is not preceded by a backslash stays where it is.
		{
			input: "a\rb\fc\\x",
			want:  "a\rb\fcx",
		},
		// Only the four CSS newlines are continuations. An escaped control
		// character that is not one of them still comes out as itself, and a
		// hex escape is not terminated by one either.
		{
			input: "a\\\x19b",
			want:  "a\x19b",
		},
		{
			input: "\\41\x19b",
			want:  "A\x19b",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := cssDecode(tt.input)
			if err != nil {
				t.Fatal(err)
			}

			shouldChange := tt.input != tt.want
			if changed != shouldChange {
				t.Errorf("unexpected changed value, want %t, have %t", shouldChange, changed)
			}

			if have != tt.want {
				t.Errorf("unexpected value, want %q, have %q", tt.want, have)
			}
		})
	}
}

func BenchmarkCSSDecode(b *testing.B) {
	tests := []string{
		"",
		"hello world",
		"test\\a\\b\\f\\n\\r\\t\\v\\?\\'\\\"\\\u0000\\12\\123\\1234\\12345\\123456\\ff01\\ff5e\\\n\\\u0000  string",
		"caf\\e9 na\\efve r\\e9sum\\e9",
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := cssDecode(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
