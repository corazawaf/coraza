// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestCompressWhiteSpace(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: "Single space",
			want:  "Single space",
		},
		{
			input: "Multiple    spaces",
			want:  "Multiple spaces",
		},
		// isLatinSpace matched raw bytes 0x85/0xA0 (meant to catch U+0085
		// NEL and U+00A0 NBSP) against a UTF-8 string one byte at a time.
		// Those bytes are never single bytes in UTF-8, but they're common
		// as the *trailing* byte of unrelated 2-byte characters, so the old
		// byte-level check spliced a byte out of the middle of the
		// character and replaced it with a literal space -- producing
		// invalid UTF-8 for input with no whitespace in that position at
		// all. See https://github.com/corazawaf/coraza/issues/1655.
		{
			input: "à ok",
			want:  "à ok",
		},
		{
			input: "Å ok",
			want:  "Å ok",
		},
		{
			input: "ą ok",
			want:  "ą ok",
		},
		// Real U+0085 (NEL) and U+00A0 (NBSP), properly UTF-8-encoded, must still be recognized and collapsed.
		{
			input: "x\u0085y",
			want:  "x y",
		},
		{
			input: "x\u00a0y",
			want:  "x y",
		},
		// Coraza transforms arbitrary request bytes, not guaranteed-UTF-8
		// strings, and ModSecurity's compressWhitespace matches the raw byte
		// (`#define NBSP 160`) regardless of encoding. A lone 0xA0 that isn't
		// part of a valid UTF-8 sequence must still collapse, or input like
		// "SELECT\xa01" would reach the operator unnormalized.
		{
			input: "SELECT\xa01",
			want:  "SELECT 1",
		},
		{
			input: "a\xa0\xa0b",
			want:  "a b",
		},
		{
			input: "a\xa0 b",
			want:  "a b",
		},
		// Raw 0x85 is not given the same treatment: isspace() in the C
		// locale ModSecurity uses never matched it, so byte-matching it here
		// would be more permissive than ModSecurity, not parity with it.
		{
			input: "SELECT\x851",
			want:  "SELECT\x851",
		},
		// Any other invalid byte is passed through untouched rather than
		// being swallowed or replaced.
		{
			input: "a\xffb",
			want:  "a\xffb",
		},
		{
			input: "a\xff\xa0b",
			want:  "a\xff b",
		},
		// 0xA0 as the trailing (continuation) byte of a valid multi-byte
		// rune is never whitespace -- this is the corruption from #1655,
		// and not limited to accented Latin letters: \u4f60 is E4 BD A0.
		{
			input: "\u4f60\u597d  \u4e16\u754c",
			want:  "\u4f60\u597d \u4e16\u754c",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := compressWhitespace(tt.input)
			if err != nil {
				t.Error(err)
			}
			wantChanged := tt.input != tt.want
			if changed != wantChanged {
				t.Errorf("input %q: changed = %t, want %t (have %q)", tt.input, changed, wantChanged, have)
			}
			if have != tt.want {
				t.Errorf("have %q, want %q", have, tt.want)
			}
		})
	}
}

func TestCompressWhiteSpaceReportsChangeOnCanonicalization(t *testing.T) {
	// A single non-space whitespace char (e.g. a tab) surrounded by
	// non-whitespace is canonicalized to a literal space -- the output
	// differs from the input, so changed must be true even though this
	// isn't a multi-char run being collapsed.
	have, changed, err := compressWhitespace("a\tb")
	if err != nil {
		t.Fatal(err)
	}
	if have != "a b" {
		t.Errorf("have %q, want %q", have, "a b")
	}
	if !changed {
		t.Errorf("changed = false, want true (have %q)", have)
	}
}

func BenchmarkCompressWhitespace(b *testing.B) {
	tests := []string{
		"",
		"test",
		"test case",
		"test    case",
		"\ttest  c\n\ras\t  ",
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := compressWhitespace(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
