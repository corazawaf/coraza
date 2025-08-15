// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// This package provides experimental way to filter rule evaluation
// during transaction processing.

package rulefilter

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/experimental/rulefilter/rftypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

// SetRuleFilter applies a RuleFilter to the transaction.
// This filter will be consulted during rule evaluation in each phase
// to determine if specific rules should be skipped for this transaction.
// It returns an error if the provided transaction is not of the expected internal type.
func SetRuleFilter(tx types.Transaction, filter rftypes.RuleFilter) error {
	internalTx, ok := tx.(*corazawaf.Transaction)
	if !ok {
		return fmt.Errorf("transaction type assertion failed, expected *corazawaf.Transaction but got %T", tx)
	}
	internalTx.SetRuleFilter(filter)
	return nil
}
