// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"
)

func TestValidateURLEncoding(t *testing.T) {
	op := &validateURLEncoding{}
	tests := []struct {
		name    string
		input   string
		invalid bool
	}{
		{"empty input", "", false},
		{"no percent encoding", "hello world", false},
		{"valid single encoding", "%2F", false},
		{"valid lowercase hex", "%2f", false},
		{"valid mixed case hex", "%2F%3a", false},
		{"valid encoding in path", "/index.html?foo=%20bar", false},
		{"null byte encoded", "%00", false},
		{"encoded ampersand", "%26", false},
		{"consecutive valid encodings", "%41%42%43", false},
		{"percent encoded as %25", "100%25 done", false},
		{"non-hex first nibble", "%GF", true},
		{"non-hex second nibble", "%2G", true},
		{"truncated at end single char", "%2", true},
		{"truncated at end no chars", "%", true},
		{"valid followed by truncated", "%2F%2", true},
		{"bare percent at end", "100%", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := op.Evaluate(nil, tc.input)
			if got != tc.invalid {
				t.Errorf("Evaluate(%q) = %v, want %v", tc.input, got, tc.invalid)
			}
		})
	}
}

func BenchmarkValidateURLEncoding(b *testing.B) {
	op := &validateURLEncoding{}
	input := "/index.html?foo=%20bar%21&baz=qux%2Fquux"
	for b.Loop() {
		op.Evaluate(nil, input)
	}
}
