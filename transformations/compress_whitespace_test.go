// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func BenchmarkCompressWhitespace(b *testing.B) {
	tests := []string{
		"",
		"test",
		"test case",
		"test    case",
		"\ttest  c\n\ras\t  ",
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := compressWhitespace(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
