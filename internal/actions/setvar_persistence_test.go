// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions_test

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/actions"
	_ "github.com/corazawaf/coraza/v3/internal/persistence"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestPersistenceSetvar(t *testing.T) {
	a, err := actions.Get("setvar")
	if err != nil {
		t.Error("failed to get setvar action")
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecPersistenceEngine default"))
	if err != nil {
		t.Error(err)
	}
	t.Run("SESSION should be set", func(t *testing.T) {
		if err := a.Init(&md{}, "SESSION.test=test"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		tx := waf.NewTransaction()
		txs := tx.(plugintypes.TransactionState)
		a.Evaluate(&md{}, txs)
		col := txs.Collection(variables.Session)
		col.FindAll()
	})
}
