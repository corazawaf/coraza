// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"

	"github.com/corazawaf/coraza/v4/types/variables"
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
}

// MatchedRule contains a list of macro expanded messages,
// matched variables and a pointer to the rule
type MatchedRule interface {
	// Message is the macro expanded message
	Message() string
	// Data is the macro expanded logdata
	Data() string
	// URI is the full request uri unparsed
	URI() string
	// TransactionID is the transaction ID
	TransactionID() string
	// Disruptive is whether this rule will perform disruptive actions (note also pass, allow, redirect are considered disruptive actions)
	Disruptive() bool
	// ServerIPAddress is the address of the server
	ServerIPAddress() string
	// ClientIPAddress is the address of the client
	ClientIPAddress() string
	// MatchedDatas is the matched variables.
	MatchedDatas() []MatchData

	Rule() RuleMetadata

	AuditLog() string

	ErrorLog() string

	Context() context.Context
}
