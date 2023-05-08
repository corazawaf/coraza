// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestRemoveWhiteSpace(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: "test",
			want:  "test",
		},
		{
			input: "t e s t",
			want:  "test",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := removeWhitespace(tt.input)
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
