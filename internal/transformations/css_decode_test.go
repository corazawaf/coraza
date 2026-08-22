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
			want:  "test\n\u000b\u000fnrtv?'\"\u0000\u0012#4EV!~\u0000  string",
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
		// CRLF is one CSS newline, so the pair is the single whitespace
		// ignored after a hex escape.
		{
			input: "aler\\74\r\n(1)",
			want:  "alert(1)",
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
