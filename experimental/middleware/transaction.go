// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type TransactionState interface {
	// ID returns the ID of the transaction.
	ID() string

	// Variables returns the TransactionVariables of the transaction.
	Variables() plugintypes.TransactionVariables

	// Collection returns a collection from the transaction.
	Collection(idx variables.RuleVariable) collection.Collection

	// DebugLogger returns the logger for this transaction.
	DebugLogger() debuglog.Logger

	// IsInterrupted will return true if the transaction was interrupted
	IsInterrupted() bool

	// Interruption returns the transaction interruption
	Interruption() *types.Interruption

	// MatchedRules returns the matched rules of the transaction
	MatchedRules() []types.MatchedRule

	// LastPhase that was evaluated
	LastPhase() types.RulePhase
}

// GetContext returns the context of the transaction and a boolean indicating if the
// transaction has a context or not.
func GetContext(tx TransactionState) (context.Context, bool) {
	itx, ok := tx.(*corazawaf.Transaction)
	if !ok {
		return context.Background(), false
	}
	return itx.Context(), true
}
