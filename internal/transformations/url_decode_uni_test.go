// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"fmt"
	"testing"
)

func TestURLDecodeUni(t *testing.T) {
	tests := []struct {
		input       string
		want        string
		wantChanged bool
	}{
		{input: "", want: "", wantChanged: false},
		{input: "helloworld", want: "helloworld", wantChanged: false},
		// '+' and valid percent-encodings are real changes.
		{input: "hello+world", want: "hello world", wantChanged: true},
		{input: "%20", want: " ", wantChanged: true},
		{input: "%u0041", want: "A", wantChanged: true},
		// A '%' that is present but does not decode (invalid hex, truncated or
		// trailing) must report changed=false.
		{input: "%zz", want: "%zz", wantChanged: false},
		{input: "%2", want: "%2", wantChanged: false},
		{input: "100%", want: "100%", wantChanged: false},
		{input: "%u00zz", want: "%u00zz", wantChanged: false},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := urlDecodeUni(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if have != tt.want {
				t.Errorf("have %q, want %q", have, tt.want)
			}
			if changed != tt.wantChanged {
				t.Errorf("input %q: changed = %t, want %t (have %q)", tt.input, changed, tt.wantChanged, have)
			}
		})
	}
}

func BenchmarkURLDecode(b *testing.B) {
	tests := []string{
		"",
		"helloworld",
		"hello+world",
		"%E3%83%8F%E3%83%AD%E3%83%BC%E3%83%AF%E3%83%BC%E3%83%AB%E3%83%89",
	}

	for _, mode := range []string{"normal", "unicode"} {
		f := urlDecode
		if mode == "unicode" {
			f = urlDecodeUni
		}
		for _, tc := range tests {
			tt := tc
			b.Run(fmt.Sprintf("%s/%s", mode, tt), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					if _, _, err := f(tt); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
