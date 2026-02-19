// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type Options = corazawaf.Options

// WAFWithOptions is an interface that allows to create transactions
// with options
type WAFWithOptions interface {
	NewTransactionWithOptions(Options) types.Transaction
}

// WAFWithRules is an interface that allows to inspect and merge rules
// across WAF instances. This is useful for connectors (e.g. nginx) that
// need to merge parent configuration rules into child locations.
type WAFWithRules interface {
	// MergeRules merges rules from the other WAF into this one.
	// Rules already present (by ID) are skipped.
	MergeRules(other WAFWithRules) error

	// RulesCount returns the number of rules in this WAF.
	RulesCount() int
}
