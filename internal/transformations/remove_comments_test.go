// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestRemoveComments(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		changed bool
	}{
		{
			name:    "no comments",
			input:   "hello world",
			want:    "hello world",
			changed: false,
		},
		{
			name:    "c-style comment",
			input:   "hello /* comment */ world",
			want:    "hello  world",
			changed: true,
		},
		{
			name:    "html comment",
			input:   "hello <!-- comment --> world",
			want:    "hello  world",
			changed: true,
		},
		{
			name:    "c-style comment only",
			input:   "/* comment */",
			want:    "\x00",
			changed: true,
		},
		{
			name:    "html comment only",
			input:   "<!-- comment -->",
			want:    "\x00",
			changed: true,
		},
		{
			name:    "unclosed c-style comment",
			input:   "hello /* unclosed",
			want:    "hello  ",
			changed: true,
		},
		{
			name:    "unclosed html comment",
			input:   "hello <!-- unclosed",
			want:    "hello  ",
			changed: true,
		},
		{
			name:    "double dash",
			input:   "hello -- rest",
			want:    "hello ",
			changed: true,
		},
		{
			name:    "hash comment",
			input:   "hello # rest",
			want:    "hello ",
			changed: true,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			changed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			have, changed, err := removeComments(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if changed != tc.changed {
				t.Errorf("changed: want %t, have %t", tc.changed, changed)
			}
			if have != tc.want {
				t.Errorf("value: want %q, have %q", tc.want, have)
			}
		})
	}
}
