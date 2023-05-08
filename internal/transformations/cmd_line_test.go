// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strings"
	"testing"
)

var cmdLineTests = []string{
	"",
	"test",
	"C^OMMAND /C DIR",
	"\"command\" /c DiR",
}

func BenchmarkCMDLine(b *testing.B) {
	for _, tc := range cmdLineTests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := cmdLine(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func FuzzCMDLine(f *testing.F) {
	for _, tc := range cmdLineTests {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, tc string) {
		data, _, err := cmdLine(tc)
		if err != nil {
			t.Error(err)
		}

		// Check simple expectations
		if strings.ContainsAny(data, `\"'^,;'ABCDEFGHIJKLMNOPQRSTUVWXYZ`) {
			t.Errorf("unexpected characters in output %s for input %s", data, tc)
		}
	})
}
