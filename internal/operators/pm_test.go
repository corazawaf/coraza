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

func TestPMSnortCapturing(t *testing.T) {
	op, err := newPM(plugintypes.OperatorOptions{
		Arguments: "A|42|C|44|F",
	})
	if err != nil {
		t.Fatalf("unexpected constructor error: %s", err)
	}

	tx := newTestTx()
	defer tx.Close()
	tx.Capture = true

	input := "xxABCDFxx"
	if !op.Evaluate(tx, input) {
		t.Fatalf("expected match on %q", input)
	}

	captures := tx.Variables().TX().Get("0")
	if len(captures) == 0 {
		t.Fatal("expected TX:0 capture, got none")
	}
	if captures[0] != "ABCDF" {
		t.Errorf("expected capture %q, got %q", "ABCDF", captures[0])
	}
}

func TestPMSnortMinLen(t *testing.T) {
	op, err := newPM(plugintypes.OperatorOptions{
		Arguments: "A|42|C",
	})
	if err != nil {
		t.Fatalf("unexpected constructor error: %s", err)
	}
	p := op.(*pm)
	// "A|42|C" decodes to 3 bytes: 'a', 0x42, 'c'
	if p.minLen != 3 {
		t.Errorf("expected minLen=3, got %d", p.minLen)
	}
}

func TestPmMinLenMultipleSpaces(t *testing.T) {
	// On main, consecutive spaces produced an empty pattern with minLen=0,
	// matching every input including empty strings.
	op, err := newPM(plugintypes.OperatorOptions{
		Arguments: "a  b",
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

	if p.Evaluate(tx, "") {
		t.Error("expected false for empty input with multiple spaces in pattern")
	}
}

func TestPMInvalidSyntax(t *testing.T) {
	tests := []struct {
		name      string
		arguments string
		wantErr   string
	}{
		{
			name:      "unclosed block at end",
			arguments: "a|4",
			wantErr:   "@pm: unclosed hex block at offset 1 (use |7C| for literal pipe)",
		},
		{
			name:      "odd number of hex digits",
			arguments: "a|4|",
			wantErr:   "@pm: odd number of hex digits in block at offset 1",
		},
		{
			name:      "invalid hex character",
			arguments: "a|4g|",
			wantErr:   `@pm: invalid hex character 'g' at offset 3`,
		},
		{
			name:      "empty hex block",
			arguments: "a||b",
			wantErr:   "@pm: empty hex block at offset 1 (use |7C| for literal pipe)",
		},
		{
			name:      "tab inside hex block",
			arguments: "|41\t42|",
			wantErr:   `@pm: invalid hex character '\t' at offset 3`,
		},
		{
			name:      "empty argument",
			arguments: "",
			wantErr:   "@pm: empty operator pattern",
		},
		{
			name:      "spaces only argument",
			arguments: "   ",
			wantErr:   "@pm: empty operator pattern",
		},
		{
			name:      "unclosed hex block after valid hex",
			arguments: "foo|41",
			wantErr:   "@pm: unclosed hex block at offset 3 (use |7C| for literal pipe)",
		},
		{
			name:      "unclosed pipe followed by non-hex",
			arguments: "foo|bar",
			wantErr:   `@pm: invalid hex character 'r' at offset 6`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newPM(plugintypes.OperatorOptions{
				Arguments: tc.arguments,
			})
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.arguments)
			}
			if err.Error() != tc.wantErr {
				t.Errorf("expected error %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}
