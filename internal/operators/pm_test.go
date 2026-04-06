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
			name:    "unclosed pipe",
			input:   "A|42",
			wantErr: true,
		},
		{
			name:    "invalid hex value",
			input:   "|ZZ|",
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
