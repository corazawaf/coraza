// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"crypto/fips140"
	"encoding/hex"
	"errors"
	"testing"
)

var sha1Vectors = []struct {
	input      string
	wantDigest string // hex-encoded
}{
	{"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	{"1234", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"},
	{"transformation", "1b3ad029ca2fb8fa799a27606993485cf5094ead"},
}

// TestSHA1 asserts the digest outside FIPS mode and, inside it (any GODEBUG=fips140 setting),
// that sha1T reports an error on every input.
func TestSHA1(t *testing.T) {
	for _, tc := range sha1Vectors {
		t.Run(tc.input, func(t *testing.T) {
			out, changed, err := sha1T(tc.input)

			if fips140.Enabled() {
				if !errors.Is(err, errSHA1NotAvailableFIPS) {
					t.Fatalf("want %v, got %v", errSHA1NotAvailableFIPS, err)
				}
				if changed {
					t.Error("expected the transformation to report an unchanged value")
				}
				if out != tc.input {
					t.Errorf("expected the input to be passed through untransformed, got %q", out)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !changed {
				t.Error("expected the transformation to report a changed value")
			}
			if got := hex.EncodeToString([]byte(out)); got != tc.wantDigest {
				t.Errorf("want %s, got %s", tc.wantDigest, got)
			}
		})
	}
}

func BenchmarkSHA1(b *testing.B) {
	if fips140.Enabled() {
		b.SkipNow()
	}
	tests := []string{
		"",
		"1234567890",
	}
	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := sha1T(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
