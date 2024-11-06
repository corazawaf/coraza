// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

var b64DecodeExtTests = []struct {
	name     string
	input    string
	expected string
}{
	{
		name:     "Valid",
		input:    "VGVzdENhc2U=",
		expected: "TestCase",
	},
	{
		name:     "Valid with \u0000",
		input:    "VGVzdABDYXNl",
		expected: "Test\x00Case",
	},
	{
		name:     "Valid without padding",
		input:    "P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		expected: "<script>alert(1)</script>",
	},
	{
		name:     "Decode with the space (invalid character)",
		input:    "PFR FU1Q+",
		expected: "<TEST>",
	},
	{
		name:     "Decoded upto a .",
		input:    "P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		expected: "<script>alert(1)</script>", // No matter where the invalid character is, it is omitted
	},
	{
		name:     "Decoded upto a . (In different position)",
		input:    "PHNjcmlwd.D5hbGVydCgxKTwvc2NyaXB0Pg==",
		expected: "<script>alert(1)</script>",
	},
	{
		name:     "Decoded upto a . (In different position)",
		input:    "PHNjcmlwdD.5hbGVydCgxKTwvc2NyaXB0Pg==",
		expected: "<script>alert(1)</script>",
	},
}

func TestBase64DecodeExt(t *testing.T) {
	for _, tt := range b64DecodeExtTests {
		t.Run(tt.name, func(t *testing.T) {
			actual, _, err := base64decodeext(tt.input)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if actual != tt.expected {
				t.Errorf("Expected %q, but got %q", tt.expected, actual)
			}
		})
	}
}
func BenchmarkB64DecodeExt(b *testing.B) {
	for _, tt := range b64DecodeExtTests {
		b.Run(tt.input, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := base64decodeext(tt.input)
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
}

func FuzzB64DecodeExt(f *testing.F) {
	for _, tc := range b64DecodeExtTests {
		f.Add(tc.input)
	}
	f.Fuzz(func(t *testing.T, tc string) {
		data, _, err := base64decodeext(tc)
		// We decode base64 within non-base64 so there is no
		// error case.
		if err != nil {
			t.Error(err)
		}

		refData, err := base64.StdEncoding.DecodeString(tc)
		// The standard library decoder will fail on many inputs ours succeeds on, but when
		// it doesn't and there are no newlines in the input, they should match.
		if err == nil && !strings.ContainsAny(tc, "\n\r") && !bytes.Equal([]byte(data), refData) {
			t.Errorf("mismatch with stdlib for input %s", tc)
		}
	})
}
