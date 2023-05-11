// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func BenchmarkSHA1(b *testing.B) {
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
