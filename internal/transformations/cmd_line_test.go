// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strings"
	"testing"
)

var cmdLineTests = []string{
	"",
	"test",
	"C^OMMAND /C DIR",
	"\"command\" /c DiR",
}

func TestCmdLine(t *testing.T) {
	tests := []struct {
		input       string
		want        string
		wantChanged bool
	}{
		{input: "", want: "", wantChanged: false},
		{input: "test", want: "test", wantChanged: false},
		// Contains a candidate character ('/') that triggers needsTransform but
		// does not change the value: changed must be reported as false.
		{input: "/etc/passwd", want: "/etc/passwd", wantChanged: false},
		{input: "/?file=../../etc/passwd", want: "/?file=../../etc/passwd", wantChanged: false},
		{input: "C^OMMAND", want: "command", wantChanged: true},
		{input: `"command"`, want: "command", wantChanged: true},
		{input: "a , b", want: "a b", wantChanged: true},
		{input: "dir /s", want: "dir/s", wantChanged: true},
		{input: "a  b", want: "a b", wantChanged: true},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := cmdLine(tt.input)
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

func BenchmarkCMDLine(b *testing.B) {
	for _, tc := range cmdLineTests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := cmdLine(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func FuzzCMDLine(f *testing.F) {
	for _, tc := range cmdLineTests {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, tc string) {
		data, _, err := cmdLine(tc)
		if err != nil {
			t.Error(err)
		}

		// Check simple expectations
		if strings.ContainsAny(data, `\"'^,;'ABCDEFGHIJKLMNOPQRSTUVWXYZ`) {
			t.Errorf("unexpected characters in output %s for input %s", data, tc)
		}
	})
}
