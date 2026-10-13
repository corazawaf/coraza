// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package operators

import (
	"runtime"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// TestPmDoesNotCopyLargeValue guards ADR-0061: testing a value against @pm must
// not allocate in proportion to the value. The matcher's Iter(string) copies the
// whole value into a []byte, which is what this used to cost on every @pm rule
// and every argument of a large body.
func TestPmDoesNotCopyLargeValue(t *testing.T) {
	op, err := newPM(plugintypes.OperatorOptions{Arguments: "attack injection exploit"})
	if err != nil {
		t.Fatal(err)
	}
	p := op.(*pm)
	tx := newTestTx()
	defer tx.Close()

	const size = 1 << 20
	value := strings.Repeat("a", size)

	const runs = 20
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < runs; i++ {
		if p.Evaluate(tx, value) {
			t.Fatal("no pattern is in the value, yet it matched")
		}
	}
	runtime.ReadMemStats(&after)

	perRun := (after.TotalAlloc - before.TotalAlloc) / runs
	// A copy of the value is size bytes per run. What is left is the matcher's
	// own bookkeeping, a few hundred bytes.
	if limit := uint64(size / 16); perRun > limit {
		t.Errorf("one @pm evaluation of a %d byte value allocated %d bytes, want at most %d", size, perRun, limit)
	}
}

// TestPmFindsPatternInLargeValue checks the match itself on a value the matcher
// reads in place: a pattern at the start, in the middle, at the very end, and
// none at all.
func TestPmFindsPatternInLargeValue(t *testing.T) {
	op, err := newPM(plugintypes.OperatorOptions{Arguments: "attack injection exploit"})
	if err != nil {
		t.Fatal(err)
	}
	p := op.(*pm)
	tx := newTestTx()
	defer tx.Close()

	filler := strings.Repeat("a", 1<<20)
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"at the start", "attack" + filler, true},
		{"in the middle", filler + "Injection" + filler, true},
		{"at the very end", filler + "EXPLOIT", true},
		{"cut off one byte short", filler + "exploi", false},
		{"absent", filler, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Evaluate(tx, tc.value); got != tc.want {
				t.Errorf("Evaluate = %v, want %v", got, tc.want)
			}
		})
	}
}
