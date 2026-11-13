// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// Not a profile: a profile cannot seed an existing REQBODY_ERROR_MSG before the helper runs.
func TestRecordRequestBodyError(t *testing.T) {
	tests := []struct {
		name      string
		processor string
		existing  string
		reason    string
		want      string
	}{
		{"first reason is prefixed", "JSON", "", "invalid JSON", "JSON: invalid JSON"},
		{"no processor, no prefix", "", "", "SecArgumentsLimit exceeded", "SecArgumentsLimit exceeded"},
		{"second reason is appended", "JSON", "JSON: SecArgumentsLimit exceeded", "invalid JSON", "JSON: SecArgumentsLimit exceeded; JSON: invalid JSON"},
		{"repeated reason is recorded once", "URLENCODED", "URLENCODED: SecArgumentsLimit exceeded", "SecArgumentsLimit exceeded", "URLENCODED: SecArgumentsLimit exceeded"},
		{"substring of an earlier reason is not a repeat", "JSON", "JSON: unexpected EOF", "EOF", "JSON: unexpected EOF; JSON: EOF"},
		{"suffix after a colon is not a repeat", "JSON", "JSON: parse error: EOF", "EOF", "JSON: parse error: EOF; JSON: EOF"},
		{"processor set after a bare reason prefixes the new one", "JSON", "SecArgumentsLimit exceeded", "invalid JSON", "SecArgumentsLimit exceeded; JSON: invalid JSON"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := corazawaf.NewTransactionVariables()
			v.RequestBodyProcessor().(*collections.Single).Set(tt.processor)
			if tt.existing != "" {
				v.RequestBodyError().(*collections.Single).Set("1")
				v.RequestBodyErrorMsg().(*collections.Single).Set(tt.existing)
			}

			bodyprocessors.RecordRequestBodyError(v, tt.reason)

			if v.RequestBodyError().Get() != "1" {
				t.Error("expected REQBODY_ERROR to be set")
			}
			if got := v.RequestBodyErrorMsg().Get(); got != tt.want {
				t.Errorf("REQBODY_ERROR_MSG: got %q, want %q", got, tt.want)
			}
		})
	}
}
