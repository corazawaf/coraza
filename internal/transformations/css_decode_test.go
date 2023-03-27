// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func BenchmarkCSSDecode(b *testing.B) {
	tests := []string{
		"",
		"hello world",
		"test\\a\\b\\f\\n\\r\\t\\v\\?\\'\\\"\\\u0000\\12\\123\\1234\\12345\\123456\\ff01\\ff5e\\\n\\\u0000  string",
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := cssDecode(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
