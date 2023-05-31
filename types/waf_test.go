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
				if want, have := string(test.expectedParts), string(parts); want != have {
					t.Errorf("unexpected parts, want %q, have %q", want, have)
				}
			}
		})
	}
}
