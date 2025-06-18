// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo && !coraza.disabled_operators.validateSchema
// +build tinygo,!coraza.disabled_operators.validateSchema

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Test that in TinyGo builds, validateSchema falls back to an unconditional match operator.
func TestNewValidateSchema_Fallback(t *testing.T) {
	op, err := NewValidateSchema(plugintypes.OperatorOptions{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// The unconditionalMatch operator always evaluates to true (match)
	if !op.Evaluate(nil, "") {
		t.Errorf("expected Evaluate to return true for empty input, got false")
	}
	if !op.Evaluate(nil, "any data") {
		t.Errorf("expected Evaluate to return true for non-empty input, got false")
	}
}
