// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestLowerCase(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "TestCase",
			want:  "testcase",
		},
		{
			input: "test\u0000case",
			want:  "test\u0000case",
		},
		{
			input: "testcase",
			want:  "testcase",
		},
		{
			input: "",
			want:  "",
		},
		{
			input: "ThIs Is A tExT fOr TeStInG lOwErCaSe FuNcTiOnAlItY.",
			want:  "this is a text for testing lowercase functionality.",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := lowerCase(tt.input)
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

func BenchmarkLowercase(b *testing.B) {
	tests := []string{
		"tesTcase",
		"ThIs Is A tExT fOr TeStInG lOwErCaSe FuNcTiOnAlItY.ThIs Is A tExT fOr TeStInG lOwErCaSe FuNcTiOnAlItY. ThIs Is A tExT fOr TeStInG lOwErCaSe FuNcTiOnAlItY.ThIs Is A tExT fOr TeStInG lOwErCaSe FuNcTiOnAlItY.",
	}
	for i := 0; i < b.N; i++ {
		for _, tt := range tests {
			b.Run(tt, func(b *testing.B) {
				for j := 0; j < b.N; j++ {
					_, _, err := lowerCase(tt)
					if err != nil {
						b.Error(err)
					}
				}
			})
		}
	}
}
