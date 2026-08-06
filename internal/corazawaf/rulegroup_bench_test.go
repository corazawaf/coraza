// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"strconv"
	"testing"
)

func BenchmarkRuleGroupAdd(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				rg := NewRuleGroup()
				for id := 1; id <= n; id++ {
					if err := rg.Add(newTestRule(id)); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
