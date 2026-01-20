// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package types

import "testing"

func TestParseAuditLogParts(t *testing.T) {
	tests := []struct {
		input            string
		expectedParts    AuditLogParts
		expectedHasError bool
	}{
		{"", nil, true},
		{"ABCDEFGHIJKZ", []AuditLogPart("BCDEFGHIJK"), false},
		{"DEFGHZ", nil, true},
		{"ABCD", nil, true},
		{"AMZ", nil, true},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			parts, err := ParseAuditLogParts(test.input)
			if test.expectedHasError {
				if err == nil {
					t.Error("expected error")
				}
			} else {
				if err != nil {
					t.Error("unexpected error")
				}

				if want, have := len(test.expectedParts), len(parts); want != have {
					t.Errorf("unexpected parts length, want %d, have %d", want, have)
				}

				for i, part := range test.expectedParts {
					if want, have := part, parts[i]; want != have {
						t.Errorf("unexpected part, want %q, have %q", want, have)
					}
				}
			}
		})
	}
}

func TestApplyAuditLogParts(t *testing.T) {
	tests := []struct {
		name             string
		base             AuditLogParts
		modification     string
		expectedParts    AuditLogParts
		expectedHasError bool
	}{
		{
			name:             "add single part",
			base:             AuditLogParts("BC"),
			modification:     "+E",
			expectedParts:    AuditLogParts("BCE"),
			expectedHasError: false,
		},
		{
			name:             "add multiple parts",
			base:             AuditLogParts("BC"),
			modification:     "+EFG",
			expectedParts:    AuditLogParts("BCEFG"),
			expectedHasError: false,
		},
		{
			name:             "add existing part (no duplicates)",
			base:             AuditLogParts("BCE"),
			modification:     "+E",
			expectedParts:    AuditLogParts("BCE"),
			expectedHasError: false,
		},
		{
			name:             "remove single part",
			base:             AuditLogParts("BCEFG"),
			modification:     "-E",
			expectedParts:    AuditLogParts("BCFG"),
			expectedHasError: false,
		},
		{
			name:             "remove multiple parts",
			base:             AuditLogParts("BCEFG"),
			modification:     "-EF",
			expectedParts:    AuditLogParts("BCG"),
			expectedHasError: false,
		},
		{
			name:             "remove non-existing part",
			base:             AuditLogParts("BC"),
			modification:     "-E",
			expectedParts:    AuditLogParts("BC"),
			expectedHasError: false,
		},
		{
			name:             "absolute value (starts with A, ends with Z)",
			base:             AuditLogParts("BC"),
			modification:     "ABCDEFZ",
			expectedParts:    AuditLogParts("BCDEF"),
			expectedHasError: false,
		},
		{
			name:             "empty modification",
			base:             AuditLogParts("BC"),
			modification:     "",
			expectedParts:    nil,
			expectedHasError: true,
		},
		{
			name:             "invalid part in addition",
			base:             AuditLogParts("BC"),
			modification:     "+X",
			expectedParts:    nil,
			expectedHasError: true,
		},
		{
			name:             "invalid part in removal",
			base:             AuditLogParts("BC"),
			modification:     "-X",
			expectedParts:    nil,
			expectedHasError: true,
		},
		{
			name:             "maintain order after addition",
			base:             AuditLogParts("BF"),
			modification:     "+E",
			expectedParts:    AuditLogParts("BEF"),
			expectedHasError: false,
		},
		{
			name:             "add all parts to empty base",
			base:             AuditLogParts(""),
			modification:     "+BCDEFGHIJK",
			expectedParts:    AuditLogParts("BCDEFGHIJK"),
			expectedHasError: false,
		},
		{
			name:             "remove all parts (A and Z remain implicit)",
			base:             AuditLogParts("BC"),
			modification:     "-BC",
			expectedParts:    AuditLogParts(""),
			expectedHasError: false,
		},
		{
			name:             "try to add mandatory part A",
			base:             AuditLogParts("BC"),
			modification:     "+A",
			expectedParts:    nil,
			expectedHasError: true,
		},
		{
			name:             "try to add mandatory part Z",
			base:             AuditLogParts("BC"),
			modification:     "+Z",
			expectedParts:    nil,
			expectedHasError: true,
		},
		{
			name:             "try to remove mandatory part A",
			base:             AuditLogParts("BC"),
			modification:     "-A",
			expectedParts:    nil,
			expectedHasError: true,
		},
		{
			name:             "try to remove mandatory part Z",
			base:             AuditLogParts("BC"),
			modification:     "-Z",
			expectedParts:    nil,
			expectedHasError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parts, err := ApplyAuditLogParts(test.base, test.modification)
			if test.expectedHasError {
				if err == nil {
					t.Error("expected error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				if want, have := len(test.expectedParts), len(parts); want != have {
					t.Errorf("unexpected parts length, want %d, have %d", want, have)
				}

				for i, part := range test.expectedParts {
					if i >= len(parts) {
						t.Errorf("missing part at index %d, want %q", i, part)
						continue
					}
					if want, have := part, parts[i]; want != have {
						t.Errorf("unexpected part at index %d, want %q, have %q", i, want, have)
					}
				}
			}
		})
	}
}
