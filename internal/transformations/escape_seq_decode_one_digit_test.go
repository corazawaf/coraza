// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestEscapeSeqDecodeOneHexDigit(t *testing.T) {
	for input, want := range map[string]string{
		`a\xdb`:  "a\xdb",
		`a\xd`:   "a\r",
		`a\x9 b`: "a\t b",
		`\XAz`:   "\nz",
		`\x41`:   "A",
		`\xg`:    "xg",
		`end\x`:  "endx",
	} {
		got, _, err := escapeSeqDecode(input)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("escapeSeqDecode(%q) = %q, want %q", input, got, want)
		}
	}
}
