// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestCJSDecode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "no escapes", input: "hello world", want: "hello world"},
		{name: "escaped backslash then zero", input: "\\\\0", want: "\\0"},
		{name: "backslash", input: "\\", want: "\\"},
		{name: "hex byte", input: "\\x41", want: "A"},
		{name: "hex high byte not clamped", input: "\\xff", want: "\xff"},
		{name: "unicode lower byte only", input: "\\u0041", want: "A"},
		{name: "unicode keeps low byte", input: "\\uabcd", want: "\xcd"},
		{name: "fullwidth A normalizes", input: "\\uff21", want: "A"},
		{name: "fullwidth ! low edge", input: "\\uff01", want: "!"},
		{name: "fullwidth ~ high edge", input: "\\uff5e", want: "~"},
		// \C simple escapes: the seven named control escapes, plus the default
		// "escape removal" (\?, \', \" and any other char just drop the backslash).
		{name: "escape bell", input: "\\a", want: "\a"},
		{name: "escape backspace", input: "\\b", want: "\b"},
		{name: "escape formfeed", input: "\\f", want: "\f"},
		{name: "escape newline", input: "\\n", want: "\n"},
		{name: "escape carriage return", input: "\\r", want: "\r"},
		{name: "escape tab", input: "\\t", want: "\t"},
		{name: "escape vertical tab", input: "\\v", want: "\v"},
		{name: "escape removal question mark", input: "\\?", want: "?"},
		{name: "escape removal single quote", input: "\\'", want: "'"},
		{name: "escape removal double quote", input: "\\\"", want: "\""},
		// \u{H...H} is the ES2015+ extended Unicode code point escape (1-6
		// hex digits in braces), used by every modern JS engine. Before
		// recognizing it, doJsDecode fell through to the generic \C branch,
		// dropping the backslash and keeping a literal "u" while copying the
		// rest through unchanged -- silently failing to decode the escape at
		// all. See https://github.com/corazawaf/coraza/issues/1653.
		{name: "extended escape decodes alert", input: "\\u{61}\\u{6c}\\u{65}\\u{72}\\u{74}", want: "alert"},
		{name: "extended escape fullwidth exclamation", input: "\\u{ff01}", want: "!"},
		{name: "extended escape single hex digit", input: "\\u{1}", want: "\x01"},
		{name: "extended escape basic", input: "\\u{41}", want: "A"},
		{name: "extended escape unterminated empty falls through", input: "\\u{", want: "u{"},
		{name: "extended escape unterminated with digits falls through", input: "\\u{41", want: "u{41"},
		{name: "extended escape invalid hex falls through", input: "\\u{zz}", want: "u{zz}"},
		// The full-width-ASCII fold must key off the fully resolved value,
		// not a fixed 4-digit count -- a leading-zero encoding of the same
		// value (5 or 6 digits) must fold identically to the 4-digit form.
		{name: "extended escape leading zero five digits folds", input: "\\u{0ff01}", want: "!"},
		{name: "extended escape leading zero six digits folds", input: "\\u{00ff01}", want: "!"},
		{name: "extended escape leading zero folds tilde", input: "\\u{0ff5e}", want: "~"},
		{name: "extended escape six digits leading zeros", input: "\\u{000061}", want: "a"},
		// 7 hex digits exceeds the 6-digit maximum: malformed, falls
		// through to the generic escape handling unchanged.
		{name: "extended escape seven digits exceeds max falls through", input: "\\u{1234567}", want: "u{1234567}"},
		// Hex digits are case-insensitive, including in a leading-zero
		// form that still has to fold.
		{name: "extended escape hex case insensitive", input: "\\u{0FF5e}", want: "~"},
		// Empty braces: no hex digits, so not a valid extended escape.
		// Falls through to generic escape handling, dropping the
		// backslash and leaving the braces literal.
		{name: "extended escape empty braces falls through", input: "\\u{}", want: "u{}"},
		// A well-formed escape for U+0000 decodes to a NUL byte rather
		// than being treated as malformed.
		{name: "extended escape zero decodes nul", input: "\\u{0}", want: "\x00"},
		// Extended and classic 4-digit escapes must decode in the same
		// pass without the extended form consuming the one after it.
		{name: "extended and classic escapes in same pass", input: "\\u{41}\\u0042", want: "AB"},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			have, changed, err := jsDecode(tt.input)
			if err != nil {
				t.Error(err)
			}
			if tt.input == tt.want && changed || tt.input != tt.want && !changed {
				t.Errorf("input %q, have %q with changed %t", tt.input, have, changed)
			}
			if have != tt.want {
				t.Errorf("have %q, want %q", have, tt.want)
			}
		})
	}
}

// TestJSDecodeOctal exercises the \OOO octal escape branch, which previously
// mis-indexed the octal digits (copying the backslash into the buffer) and
// clamped high bytes (\200-\377) to 0x7f.
func TestJSDecodeOctal(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "single low byte", input: "\\101", want: "A"},
		{name: "nul byte", input: "\\0", want: "\x00"},
		{name: "one digit", input: "\\1", want: "\x01"},
		{name: "two digits at end of input", input: "\\16", want: "\x0e"},
		// "script" encoded as octal escapes
		{name: "script payload", input: "\\163\\143\\162\\151\\160\\164", want: "script"},
		// High bytes must not be clamped to 0x7f.
		{name: "max byte", input: "\\377", want: "\xff"},
		{name: "high byte 0x80", input: "\\200", want: "\x80"},
		// A value that would exceed one byte keeps only two digits, the third
		// character is emitted literally.
		{name: "overflow truncates to two digits", input: "\\400", want: " 0"},
		{name: "leading digit > 3 truncates", input: "\\477", want: "'7"},
		// Consumption stops at the first non-octal digit.
		{name: "stops at non-octal digit", input: "\\168", want: "\x0e8"},
		// Surrounding literals are preserved (the XSS-style wrapper).
		{name: "wrapped in angle brackets", input: "<\\163\\143\\162\\151\\160\\164>", want: "<script>"},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			have, changed, err := jsDecode(tt.input)
			if err != nil {
				t.Error(err)
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

func BenchmarkJSDecode(b *testing.B) {
	tests := []string{
		"",
		"hello world",
		"\\a\\b\\f\\n\\r\\t\\v\\u0000\\?\\'\\\"\\0\\12\\123\\x00\\xff",
		"\\u{61}\\u{6c}\\u{65}\\u{72}\\u{74}",
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := jsDecode(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
