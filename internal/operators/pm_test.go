// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestMinPatternLen(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		want     int
	}{
		{"single pattern", []string{"hello"}, 5},
		{"multiple patterns", []string{"hello", "hi", "hey"}, 2},
		{"empty patterns only", []string{"", ""}, 0},
		{"mixed with empty", []string{"abc", "", "de"}, 0},
		{"single char", []string{"a", "longer"}, 1},
		{"no patterns", []string{}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := minPatternLen(tc.patterns); got != tc.want {
				t.Errorf("minPatternLen(%v) = %d, want %d", tc.patterns, got, tc.want)
			}
		})
	}
}

func newTestTx() *corazawaf.Transaction {
	return corazawaf.NewWAF().NewTransaction()
}

func TestPmMinLenShortCircuit(t *testing.T) {
	op, err := newPM(plugintypes.OperatorOptions{
		Arguments: "attack injection exploit",
	})
	if err != nil {
		t.Fatal(err)
	}

	p := op.(*pm)
	// Shortest pattern is "attack" (6 chars)
	if p.minLen != 6 {
		t.Fatalf("expected minLen=6, got %d", p.minLen)
	}

	tx := newTestTx()
	defer tx.Close()

	// Input shorter than minLen — must return false without hitting Aho-Corasick
	if p.Evaluate(tx, "abc") {
		t.Error("expected false for input shorter than minLen")
	}

	// Input that matches
	if !p.Evaluate(tx, "an attack here") {
		t.Error("expected true for input containing 'attack'")
	}

	// Input at exact minLen but no match
	if p.Evaluate(tx, "abcdef") {
		t.Error("expected false for non-matching input at exact minLen")
	}
}

func TestPmMinLenWithSingleCharPattern(t *testing.T) {
	// When one pattern is a single char, minLen=1 so only empty strings are skipped
	op, err := newPM(plugintypes.OperatorOptions{
		Arguments: "a longpattern",
	})
	if err != nil {
		t.Fatal(err)
	}

	p := op.(*pm)
	if p.minLen != 1 {
		t.Fatalf("expected minLen=1, got %d", p.minLen)
	}

	tx := newTestTx()
	defer tx.Close()

	// Empty input is shorter than minLen=1
	if p.Evaluate(tx, "") {
		t.Error("expected false for empty input")
	}

	// Single char that matches
	if !p.Evaluate(tx, "a") {
		t.Error("expected true for matching single char")
	}
}

func BenchmarkPmShortInput(b *testing.B) {
	op, err := newPM(plugintypes.OperatorOptions{
		Arguments: "select insert update delete from where union injection script alert",
	})
	if err != nil {
		b.Fatal(err)
	}
	p := op.(*pm)

	tx := newTestTx()
	b.Cleanup(func() { tx.Close() })

	b.Run("below_minLen", func(b *testing.B) {
		// "from" is shortest at 4 chars, input is 3
		b.ReportAllocs()
		for b.Loop() {
			p.Evaluate(tx, "abc")
		}
	})

	b.Run("at_minLen_no_match", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			p.Evaluate(tx, "abcd")
		}
	})

	b.Run("longer_no_match", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			p.Evaluate(tx, "this is a perfectly normal request with no suspicious content")
		}
	})

	b.Run("longer_match", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			p.Evaluate(tx, "select * from users where 1=1")
		}
	})
}
