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
//
// Implementations of WAFWithRules are allowed to mutate their internal
// rule set when MergeRules is called. To preserve the concurrency
// guarantees of the WAF, MergeRules must only be used during WAF
// initialization, before any transactions are created or processed.
// Calling MergeRules concurrently with transaction processing, or
// concurrently from multiple goroutines, is not safe unless explicitly
// documented otherwise by the implementation.
type WAFWithRules interface {
	// MergeRules merges rules from the other WAF into this one.
	// Rules already present (by ID) are skipped.
	//
	// MergeRules mutates the receiver's rule set and is intended to be
	// used only at configuration time (for example, when building child
	// location configurations from a parent). It must not be called
	// after transactions have started to be created or processed, and
	// it must not be invoked concurrently with transaction processing
	// or from multiple goroutines unless the implementation documents
	// stronger concurrency guarantees.
	MergeRules(other WAFWithRules) error

	// RulesCount returns the number of rules in this WAF.
	RulesCount() int
}
