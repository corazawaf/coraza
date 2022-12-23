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
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, err := utf8ToUnicode(tt.input)
			if err != nil {
				t.Error(err)
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
				if _, err := utf8ToUnicode(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
