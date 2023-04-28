// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"fmt"
	"testing"
)

func BenchmarkURLDecode(b *testing.B) {
	tests := []string{
		"",
		"helloworld",
		"hello+world",
		"%E3%83%8F%E3%83%AD%E3%83%BC%E3%83%AF%E3%83%BC%E3%83%AB%E3%83%89",
	}

	for _, mode := range []string{"normal", "unicode"} {
		f := urlDecode
		if mode == "unicode" {
			f = urlDecodeUni
		}
		for _, tc := range tests {
			tt := tc
			b.Run(fmt.Sprintf("%s/%s", mode, tt), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					if _, _, err := f(tt); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
