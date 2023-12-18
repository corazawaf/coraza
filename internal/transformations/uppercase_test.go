// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestUpperCase(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "TestCase",
			want:  "TESTCASE",
		},
		{
			input: "test\u0000case",
			want:  "TEST\u0000CASE",
		},
		{
			input: "TESTCASE",
			want:  "TESTCASE",
		},
		{
			input: "",
			want:  "",
		},
		{
			input: "ThIs Is A tExT fOr TeStInG uPPerCAse FuNcTiOnAlItY.",
			want:  "THIS IS A TEXT FOR TESTING UPPERCASE FUNCTIONALITY.",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := upperCase(tt.input)
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

func BenchmarkUppercase(b *testing.B) {
	tests := []string{
		"tesTcase",
		"ThIs Is A tExT fOr TeStInG lOwErCaSe FuNcTiOnAlItY.ThIs Is A tExT fOr TeStInG lOwErCaSe FuNcTiOnAlItY. ThIs Is A tExT fOr TeStInG lOwErCaSe FuNcTiOnAlItY.ThIs Is A tExT fOr TeStInG lOwErCaSe FuNcTiOnAlItY.",
	}
	for i := 0; i < b.N; i++ {
		for _, tt := range tests {
			b.Run(tt, func(b *testing.B) {
				for j := 0; j < b.N; j++ {
					_, _, err := upperCase(tt)
					if err != nil {
						b.Error(err)
					}
				}
			})
		}
	}
}
