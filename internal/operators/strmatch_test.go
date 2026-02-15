// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/stretchr/testify/require"
)

func TestStrmatch(t *testing.T) {
	t.Run("test substring matching", func(t *testing.T) {
		strmatch, err := newStrmatch(plugintypes.OperatorOptions{
			Arguments: "test",
		})
		require.NoError(t, err, "unexpected error")

		testCases := map[string]bool{
			"test":           true,
			"this is a test": true,
			"testing":        true,
			"atest":          true,
			"atesta":         true,
			"no match":       false,
			"":               false,
			"TEST":           false, // case sensitive
		}

		for value, want := range testCases {
			t.Run(value, func(t *testing.T) {
				if have := strmatch.Evaluate(nil, value); want != have {
					t.Errorf("unexpected result for '%s': want %v, have %v", value, want, have)
				}
			})
		}
	})

	t.Run("test case sensitivity", func(t *testing.T) {
		strmatch, err := newStrmatch(plugintypes.OperatorOptions{
			Arguments: "WebZIP",
		})
		require.NoError(t, err, "unexpected error")

		testCases := map[string]bool{
			"WebZIP":                true,
			"This is WebZIP client": true,
			"webzip":                false,
			"WEBZIP":                false,
			"Mozilla/5.0 (WebZIP)":  true,
		}

		for value, want := range testCases {
			t.Run(value, func(t *testing.T) {
				require.Equal(t, want, strmatch.Evaluate(nil, value), "unexpected result for '%s'", value)
			})
		}
	})

}
