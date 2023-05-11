// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestReplaceComments(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "This is/*this is a comment*/text",
			want:  "This is text",
		},
		{
			input: "/*this is a comment*/a comment",
			want:  " a comment",
		},
		{
			input: "/**/",
			want:  " ",
		},
		{
			input: "/*comment",
			want:  " ",
		},
		{
			input: "Not a comment",
			want:  "Not a comment",
		},
		{
			input: "",
			want:  "",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := replaceComments(tt.input)
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
