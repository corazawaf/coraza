// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestEscapeSeqDecode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: "TestCase",
			want:  "TestCase",
		},
		{
			input: "\\",
			want:  "\\",
		},
		{
			input: "\\\\u0000",
			want:  "\\u0000",
		},
		{
			input: "\\a\\b\\f\\n\\r\\t\\v\\u0000\\?\\'\\\"\\0\\12\\123\\x00\\xff",
			want:  "\a\b\f\n\r\t\vu0000?'\"\x00\nS\x00\xff",
		},
		{
			input: "\\z",
			want:  "z",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := escapeSeqDecode(tt.input)
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

// Sequences above \377 do not fit in a byte and have to be truncated to their low byte;
// this test ensures that the escape sequence decoder does not return an error for those sequences,
// and that it returns the expected low byte value instead of saturating to 0xff
func TestEscapeSeqDecodeOctal(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "single low byte", input: "\\101", want: "A"},
		{name: "nul byte", input: "\\0", want: "\x00"},
		{name: "one digit", input: "\\1", want: "\x01"},
		{name: "two digits at end of input", input: "\\16", want: "\x0e"},
		{name: "max byte", input: "\\377", want: "\xff"},
		// Above \377 the value wraps to its low byte instead of saturating.
		{name: "wraps to nul", input: "\\400", want: "\x00"},
		{name: "wraps to newline", input: "\\412", want: "\n"},
		{name: "wraps to printable", input: "\\521", want: "Q"},
		{name: "wraps to high byte", input: "\\666", want: "\xb6"},
		{name: "max octal wraps", input: "\\777", want: "\xff"},
		// Consumption stops after 3 digits, the 4th is emitted literally.
		{name: "stops after three digits", input: "\\0123", want: "\n3"},
		// "script" encoded as octal escapes above \377.
		{name: "script payload", input: "\\563\\543\\562\\551\\560\\564", want: "script"},
		{name: "wrapped in angle brackets", input: "<\\563\\543\\562\\551\\560\\564>", want: "<script>"},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			have, changed, err := escapeSeqDecode(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if have != tt.want {
				t.Errorf("input %q: have %q (% x), want %q (% x)", tt.input, have, have, tt.want, tt.want)
			}
			if !changed {
				t.Errorf("input %q: expected changed to be true", tt.input)
			}
		})
	}
}

func BenchmarkEscapeSeqDecode(b *testing.B) {
	tests := []string{
		"",
		"hello world",
		"\\a\\b\\f\\n\\r\\t\\v\\u0000\\?\\'\\\"\\0\\12\\123\\x00\\xff",
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := escapeSeqDecode(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
