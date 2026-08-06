// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"crypto/fips140"
	"encoding/hex"
	"errors"
	"testing"
)

var md5Vectors = []struct {
	input      string
	wantDigest string // hex-encoded
}{
	{"", "d41d8cd98f00b204e9800998ecf8427e"},
	{"1234", "81dc9bdb52d04dc20036dbd8313ed055"},
	{"transformation", "3935f8feee087b4547de27296ec777b9"},
}

func TestMD5(t *testing.T) {
	if fips140.Enabled() {
		return
	}
	for _, tc := range md5Vectors {
		t.Run(tc.input, func(t *testing.T) {
			out, changed, err := md5T(tc.input)
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

// TestMD5FIPSGuard asserts that in FIPS 140-3 mode md5 is unavailable and reports an error on
// every input, including the empty-string fast path, rather than silently returning a digest.
func TestMD5FIPSGuard(t *testing.T) {
	if !fips140.Enabled() {
		return
	}
	for _, tc := range md5Vectors {
		t.Run(tc.input, func(t *testing.T) {
			out, changed, err := md5T(tc.input)
			if !errors.Is(err, errMD5NotAvailableFIPS) {
				t.Fatalf("want %v, got %v", errMD5NotAvailableFIPS, err)
			}
			if changed {
				t.Error("expected the transformation to report an unchanged value")
			}
			if out != tc.input {
				t.Errorf("expected the input to be passed through untransformed, got %q", out)
			}
		})
	}
}

func BenchmarkMD5(b *testing.B) {
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
				if _, _, err := md5T(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
