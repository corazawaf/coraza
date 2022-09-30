// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import "github.com/corazawaf/coraza/v3/types"

// Rule is a rule executed against a transaction.
type Rule interface {
	// Evaluate evaluates the rule, returning data related to matches if any.
	Evaluate(state TransactionState) []types.MatchData
}

// RuleMetadata is information about a rule parsed from directives.
type RuleMetadata interface {
	// GetID returns the ID of the rule.
	GetID() int

	// GetParentID returns the ID of the parent of the rule for a chained rule.
	GetParentID() int

	// Status returns the status to set if the rule matches.
	Status() int
}
