// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func BenchmarkJSDecode(b *testing.B) {
	tests := []string{
		"",
		"hello world",
		"\\a\\b\\f\\n\\r\\t\\v\\u0000\\?\\'\\\"\\0\\12\\123\\x00\\xff",
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := jsDecode(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
