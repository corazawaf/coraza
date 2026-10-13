// Copyright 2026 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestNormalisePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "", want: ""},
		{input: ".", want: ""},
		{input: "./", want: ""},
		{input: "/", want: "//"},
		{input: "//", want: "//"},
		{input: "foo//bar", want: "foo/bar"},
		{input: "foo/bar/", want: "foo/bar/"},
		{input: "foo/../bar", want: "bar"},
		{input: "foo/..", want: ""},
		{input: "foo/../", want: ""},
		{input: `foo\..\bar`, want: `foo\..\bar`},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := normalisePath(tt.input)
			if err != nil {
				t.Fatal(err)
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
