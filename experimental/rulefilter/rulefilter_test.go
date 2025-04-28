// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
package rulefilter

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// Simple implementation for testing.
type mockRuleFilter struct{}

func (m *mockRuleFilter) ShouldIgnore(types.RuleMetadata) bool {
	return true
}

// Embed the interface to avoid implementing all methods initially.
// We only need this struct to *not* be a *corazawaf.Transaction.
type mockTransaction struct {
	types.Transaction
}

func TestSetRuleFilter(t *testing.T) {
	// Note: Verification that the filter *works* is covered by internal tests.
	// This test specifically checks whether SetRuleFilter returns the expected error.

	t.Run("set success", func(t *testing.T) {
		conf := coraza.NewWAFConfig()
		waf, err := coraza.NewWAF(conf)
		require.NoError(t, err)
		tx := waf.NewTransaction()
		require.NotNil(t, tx)

		filter := &mockRuleFilter{}

		err = SetRuleFilter(tx, filter)
		require.NoError(t, err, "Setting filter on standard tx should succeed")
	})

	t.Run("set success for nil", func(t *testing.T) {
		conf := coraza.NewWAFConfig()
		waf, err := coraza.NewWAF(conf)
		require.NoError(t, err)
		tx := waf.NewTransaction()
		require.NotNil(t, tx)

		// First set a filter
		initialFilter := &mockRuleFilter{}
		err = SetRuleFilter(tx, initialFilter)
		require.NoError(t, err)

		// Now clear it by setting nil
		err = SetRuleFilter(tx, nil)
		require.NoError(t, err, "Setting nil filter should succeed")
	})

	t.Run("fail wrong transaction type", func(t *testing.T) {
		// Use our mockTransaction which fulfills the interface but isn't the internal type
		mockTx := &mockTransaction{}
		filter := &mockRuleFilter{}

		err := SetRuleFilter(mockTx, filter)
		require.Error(t, err, "Setting filter on incorrect tx type should fail")
	})

}
