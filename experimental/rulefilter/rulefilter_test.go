// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
package rulefilter

import (
	"testing"

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
		if err != nil {
			t.Fatalf("Failed to create WAF: %v", err)
		}
		tx := waf.NewTransaction()
		if tx == nil {
			t.Fatal("Expected non-nil transaction, but got nil")
		}

		filter := &mockRuleFilter{}

		err = SetRuleFilter(tx, filter)
		if err != nil {
			t.Fatalf("Setting filter should succeed, but got error: %v", err)
		}
	})

	t.Run("set success for nil", func(t *testing.T) {
		conf := coraza.NewWAFConfig()
		waf, err := coraza.NewWAF(conf)
		if err != nil {
			t.Fatalf("Failed to create WAF: %v", err)
		}
		tx := waf.NewTransaction()
		if tx == nil {
			t.Fatal("Expected non-nil transaction, but got nil")
		}

		// resetting the filter should not fail
		err = SetRuleFilter(tx, nil)
		if err != nil {
			t.Fatalf("Setting nil filter should succeed, but got error: %v", err)
		}
	})

	t.Run("fail wrong transaction type", func(t *testing.T) {
		// Use our mockTransaction which fulfills the interface but isn't the internal type
		mockTx := &mockTransaction{}
		filter := &mockRuleFilter{}

		err := SetRuleFilter(mockTx, filter)
		if err == nil {
			t.Fatal("Setting filter on incorrect tx type should fail")
		}
	})
}
