// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestUTF8ToUnicode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: "hello world",
			want:  "hello world",
		},
		{
			input: "ハローワールド",
			want:  "%u30cf%u30ed%u30fc%u30ef%u30fc%u30eb%u30c9",
		},
		{
			input: "Hello ハローワールド world",
			want:  "Hello %u30cf%u30ed%u30fc%u30ef%u30fc%u30eb%u30c9 world",
		},
		{
			input: "ĤéllŌ wŏrld",
			want:  "%u0124%u00e9ll%u014c w%u014frld",
		},
		{
			input: "hello\000world",
			want:  "hello\000world",
		},
		{
			input: "hello 🍺",
			want:  "hello %u1f37a",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := utf8ToUnicode(tt.input)
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

func BenchmarkUTF8ToUnicode(b *testing.B) {
	tests := []string{
		"",
		"hello world",
		"ハローワールド",
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := utf8ToUnicode(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
