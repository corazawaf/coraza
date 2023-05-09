// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

var b64DecodeTests = []string{
	"VGVzdENhc2U=",
	"P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
	"VGVzdABDYXNl",
}

func BenchmarkB64Decode(b *testing.B) {
	for _, tt := range b64DecodeTests {
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := base64decode(tt)
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
}

func FuzzB64Decode(f *testing.F) {
	for _, tc := range b64DecodeTests {
		f.Add(tc)
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
