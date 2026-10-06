// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package strings

import "testing"

// txIDLen is the length internal/corazawaf/waf.go asks for when it builds a
// transaction ID, which is the hot path for RandomString: one call per
// transaction.
const txIDLen = 19

// BenchmarkRandomString measures the serial cost.
func BenchmarkRandomString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = RandomString(txIDLen)
	}
}

// BenchmarkRandomStringParallel is the one that matters: run it with
// -cpu=1,4,16 and the per-op cost should go *down* as cores are added. The
// previous mutex-guarded implementation went the other way (116ns at -cpu=1,
// 244ns at -cpu=16) because every transaction contended on a single lock.
func BenchmarkRandomStringParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = RandomString(txIDLen)
		}
	})
}
