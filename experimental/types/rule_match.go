// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/corazawaf/coraza/v3/types/variables"
)

// MatchData works like VariableKey but is used for logging,
// so it contains the collection as a string, and it's value
type MatchData interface {
	// Variable
	Variable() variables.RuleVariable
	// Key of the variable, blank if no key is required
	Key() string
	// Value of the current VARIABLE:KEY
	Value() string
	// Message is the expanded macro message
	Message() string
	// Data is the expanded logdata of the macro
	Data() string
	// Chain depth of variable match
	ChainLevel() int
	// Metadata of the matched data
	Metadata() DataMetadataList
}
