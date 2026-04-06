// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestParsePMArgs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
		wantErr  bool
	}{
		{
			name:     "plain patterns",
			input:    "hello world",
			expected: []string{"hello", "world"},
		},
		{
			name:     "single pattern",
			input:    "test",
			expected: []string{"test"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "only spaces",
			input:    "   ",
			expected: nil,
		},
		{
			name:     "snort hex inline: A|42|C|44|F",
			input:    "A|42|C|44|F",
			expected: []string{"abcdf"},
		},
		{
			name:     "snort hex only: |41|",
			input:    "|41|",
			expected: []string{"a"},
		},
		{
			name:     "snort multiple hex bytes in one block: |41 42 43|",
			input:    "|41 42 43|",
			expected: []string{"abc"},
		},
		{
			name:     "snort CRLF: |0d 0a|",
			input:    "|0d 0a|",
			expected: []string{"\r\n"},
		},
		{
			name:     "snort non-letter byte: |01|",
			input:    "|01|",
			expected: []string{"\x01"},
		},
		{
			name:     "uppercase literal normalised to lowercase",
			input:    "ABC",
			expected: []string{"abc"},
		},
		{
			name:     "snort hex letter normalised to lowercase: |41|",
			input:    "|41|",
			expected: []string{"a"},
		},
		{
			name:     "multiple patterns with snort syntax",
			input:    "A|42|C |44|F",
			expected: []string{"abc", "df"},
		},
		{
			name:     "snort syntax mixed with plain pattern",
			input:    "plain |41 42| mixed",
			expected: []string{"plain", "ab", "mixed"},
		},
		{
			name:    "unclosed pipe",
			input:   "A|42",
			wantErr: true,
		},
		{
			name:    "invalid hex value at end of pipe block",
			input:   "|ZZ|",
			wantErr: true,
		},
		{
			name:    "invalid hex value before space inside pipe block",
			input:   "|ZZ FF|",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePMArgs(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parsePMArgs(%q) expected error but got nil, result: %v", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("parsePMArgs(%q) unexpected error: %v", tt.input, err)
				return
			}
			if len(got) != len(tt.expected) {
				t.Errorf("parsePMArgs(%q) = %v (len %d), want %v (len %d)", tt.input, got, len(got), tt.expected, len(tt.expected))
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("parsePMArgs(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestPMSnortSyntax(t *testing.T) {
	tests := []struct {
		name      string
		param     string
		input     string
		wantMatch bool
	}{
		{
			name:      "hex bytes inline: A|42|C|44|F matches ABCDF",
			param:     "A|42|C|44|F",
			input:     "ABCDF",
			wantMatch: true,
		},
		{
			name:      "hex bytes inline: A|42|C|44|F does not match AXYF",
			param:     "A|42|C|44|F",
			input:     "AXYF",
			wantMatch: false,
		},
		{
			name:      "hex CRLF matches CRLF in input",
			param:     "|0d 0a|",
			input:     "line1\r\nline2",
			wantMatch: true,
		},
		{
			name:      "case insensitive: lowercase input matches uppercase pattern encoded as hex",
			param:     "A|42|C|44|F",
			input:     "abcdf",
			wantMatch: true,
		},
		{
			name:      "plain pattern still works",
			param:     "foo bar",
			input:     "here is bar",
			wantMatch: true,
		},
		{
			name:      "plain pattern no match",
			param:     "foo bar",
			input:     "nothing here",
			wantMatch: false,
		},
		{
			name:      "snort hex only pattern matches",
			param:     "|41 42 43|",
			input:     "xABCy",
			wantMatch: true,
		},
		{
			name:      "snort non-printable byte matches",
			param:     "prefix|01|suffix",
			input:     "prefix\x01suffix",
			wantMatch: true,
		},
	}

	waf := corazawaf.NewWAF()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, err := newPM(plugintypes.OperatorOptions{Arguments: tt.param})
			if err != nil {
				t.Fatalf("newPM(%q) unexpected error: %v", tt.param, err)
			}
			tx := waf.NewTransaction()
			got := op.Evaluate(tx, tt.input)
			if got != tt.wantMatch {
				t.Errorf("pm(%q).Evaluate(%q) = %v, want %v", tt.param, tt.input, got, tt.wantMatch)
			}
		})
	}
}

func TestNewPMInvalidArgs(t *testing.T) {
	invalidCases := []struct {
		name  string
		param string
	}{
		{name: "unclosed pipe", param: "A|42"},
		{name: "invalid hex", param: "|ZZ|"},
		{name: "invalid hex before space in pipe", param: "|ZZ FF|"},
	}

	for _, tt := range invalidCases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newPM(plugintypes.OperatorOptions{Arguments: tt.param})
			if err == nil {
				t.Errorf("newPM(%q) expected error but got nil", tt.param)
			}
		})
	}
}

func TestPMEvaluateWithCapture(t *testing.T) {
	waf := corazawaf.NewWAF()

	t.Run("capture mode returns matches", func(t *testing.T) {
		op, err := newPM(plugintypes.OperatorOptions{Arguments: "foo bar baz"})
		if err != nil {
			t.Fatalf("newPM: unexpected error: %v", err)
		}
		tx := waf.NewTransaction()
		tx.Capture = true
		if !op.Evaluate(tx, "foo and bar") {
			t.Error("expected match but got none")
		}
	})

	t.Run("capture mode no match returns false", func(t *testing.T) {
		op, err := newPM(plugintypes.OperatorOptions{Arguments: "foo bar"})
		if err != nil {
			t.Fatalf("newPM: unexpected error: %v", err)
		}
		tx := waf.NewTransaction()
		tx.Capture = true
		if op.Evaluate(tx, "nothing to see here") {
			t.Error("expected no match but got one")
		}
	})

	t.Run("capture mode stops after 10 matches", func(t *testing.T) {
		// Build a pattern that can match many times in one string.
		// "a" will match every 'a' in the input.
		op, err := newPM(plugintypes.OperatorOptions{Arguments: "a"})
		if err != nil {
			t.Fatalf("newPM: unexpected error: %v", err)
		}
		tx := waf.NewTransaction()
		tx.Capture = true
		// 15 'a' chars separated by '-' to ensure 15 distinct matches.
		input := "a-a-a-a-a-a-a-a-a-a-a-a-a-a-a"
		if !op.Evaluate(tx, input) {
			t.Error("expected match but got none")
		}
	})
}
