// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo && !coraza.disabled_operators.validateSchema

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/stretchr/testify/require"
)

// Test that in TinyGo builds, validateSchema falls back to an unconditional match operator.
func TestNewValidateSchema_Fallback(t *testing.T) {
	op, err := NewValidateSchema(plugintypes.OperatorOptions{})
	require.NoError(t, err, "expected no error")
	// The unconditionalMatch operator always evaluates to true (match)
	require.True(t, op.Evaluate(nil, ""), "expected Evaluate to return true for empty input, got false")
	require.True(t, op.Evaluate(nil, "any data"), "expected Evaluate to return true for non-empty input, got false")
}
