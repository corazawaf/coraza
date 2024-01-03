// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

var b64DecodeTests = []struct {
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
		input:    "VGVzdENhc2U",
		expected: "TestCase",
	},
	{
		name:     "Valid without longer padding",
		input:    "PA==",
		expected: "<",
	},
	{
		name:     "valid <TEST>",
		input:    "PFRFU1Q+",
		expected: "<TEST>",
	},
	{
		name:     "Malformed base64 encoding",
		input:    "PHNjcmlwd",
		expected: "<scrip",
	},
	{
		name:     "decoded up to the space (invalid character)",
		input:    "PFR FU1Q+",
		expected: "<T",
	},
	{
		name:     "decoded up to the dot (invalid character)",
		input:    "P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		expected: "", // Only the P character does not result in a printable character conversion.
	},
	{
		name:     "decoded up to the dot (invalid character)",
		input:    "PHNjcmlwd.D5hbGVydCgxKTwvc2NyaXB0Pg==",
		expected: "<scrip",
	},
	{
		name:     "decoded up to the dot (invalid character)",
		input:    "PHNjcmlwdD.5hbGVydCgxKTwvc2NyaXB0Pg==",
		expected: "<script",
	},
	{
		name:     "decoded up to the dash (invalid character for base64, only valid for Base64url)",
		input:    "PFRFU1Q-",
		expected: "<TEST",
	},
	// The following tests are from the golang base64 decoder tests
	// Source: https://github.com/golang/go/blob/c95fe91d0715dc0a8d55ac80a80f383c3635548b/src/encoding/base64/base64_test.go#L25C4-L49
	{
		name:     "golang test - RFC 3548 examples",
		input:    "FPucA9l+",
		expected: "\x14\xfb\x9c\x03\xd9\x7e",
	},
	{
		name:     "golang test - RFC 3548 examples",
		input:    "FPucA9k=",
		expected: "\x14\xfb\x9c\x03\xd9",
	},
	{
		name:     "golang test - RFC 3548 examples",
		input:    "FPucAw==",
		expected: "\x14\xfb\x9c\x03",
	},
	{
		name:     "golang test - RFC 4648 examples",
		input:    "",
		expected: "",
	},
	{
		name:     "golang test - RFC 4648 examples",
		input:    "Zg==",
		expected: "f",
	},
	{
		name:     "golang test - RFC 4648 examples",
		input:    "Zm8=",
		expected: "fo",
	},
	{
		name:     "golang test - RFC 4648 examples",
		input:    "Zm9v",
		expected: "foo",
	},
	{
		name:     "golang test - RFC 4648 examples",
		input:    "Zm9vYg==",
		expected: "foob",
	},
	{
		name:     "golang test - RFC 4648 examples",
		input:    "Zm9vYmE=",
		expected: "fooba",
	},
	{
		name:     "golang test - RFC 4648 examples",
		input:    "Zm9vYmFy",
		expected: "foobar",
	},
	{
		name:     "golang test - Wikipedia examples",
		input:    "c3VyZS4=",
		expected: "sure.",
	},
	{
		name:     "golang test - Wikipedia examples",
		input:    "c3VyZQ==",
		expected: "sure",
	},
	{
		name:     "golang test - Wikipedia examples",
		input:    "c3Vy",
		expected: "sur",
	},
	{
		name:     "golang test - Wikipedia examples",
		input:    "c3U=",
		expected: "su",
	},
	{
		name:     "golang test - Wikipedia examples",
		input:    "bGVhc3VyZS4=",
		expected: "leasure.",
	},
	{
		name:     "golang test - Wikipedia examples",
		input:    "ZWFzdXJlLg==",
		expected: "easure.",
	},
	{
		name:     "golang test - Wikipedia examples",
		input:    "YXN1cmUu",
		expected: "asure.",
	},
}

func TestBase64Decode(t *testing.T) {
	for _, tt := range b64DecodeTests {
		t.Run(tt.name, func(t *testing.T) {
			actual, _, err := base64decode(tt.input)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if actual != tt.expected {
				t.Errorf("Expected %q, but got %q", tt.expected, actual)
			}
		})
	}
}
func BenchmarkB64Decode(b *testing.B) {
	for _, tt := range b64DecodeTests {
		b.Run(tt.input, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := base64decode(tt.input)
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
}

func FuzzB64Decode(f *testing.F) {
	for _, tc := range b64DecodeTests {
		f.Add(tc.input)
	}
	f.Fuzz(func(t *testing.T, tc string) {
		data, _, err := base64decode(tc)
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
