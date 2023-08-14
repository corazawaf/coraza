// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions_test

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/actions"
)

func TestInitcolInit(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig()) //nolint:errcheck
	initcol, err := actions.Get("initcol")
	if err != nil {
		t.Error(err)
	}
	t.Run("invalid argument", func(t *testing.T) {
		if err := initcol.Init(&md{}, "test"); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("editable variable", func(t *testing.T) {
		if err := initcol.Init(&md{}, "session=abcdef"); err != nil {
			t.Error(err)
		}
		txs := waf.NewTransaction().(plugintypes.TransactionState)
		initcol.Evaluate(&md{}, txs)
	})
}
