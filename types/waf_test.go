package types

import "testing"

func TestParseAuditLogParts(t *testing.T) {
	tests := map[string]bool{
		"":             true,
		"ABCDEFGHIJKZ": false,
		"DEFGHZ":       true,
		"ABCD":         true,
		"AMZ":          true,
	}

	for input, expectedErr := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := ParseAuditLogParts(input)
			if expectedErr {
				if err == nil {
					t.Error("expected error")
				}
			} else {
				if err != nil {
					t.Error("unexpected error")
				}
			}
		})
	}
}
