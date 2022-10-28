// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package types

import "github.com/corazawaf/coraza/v3/types/variables"

// MatchData works like VariableKey but is used for logging,
// so it contains the collection as a string, and it's value
type MatchData interface {
	// VariableName stored for cache
	VariableName() string
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
	// IsNil is used to check whether the MatchData is empty
	IsNil() bool
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
	// Disruptive is whether this rule will block the request
	Disruptive() bool
	// ServerIPAddress is the address of the server
	ServerIPAddress() string
	// ClientIPAddress is the address of the client
	ClientIPAddress() string
	// MatchedDatas is the matched variables.
	MatchedDatas() []MatchData

	Rule() RuleMetadata

	AuditLog(code int) string
	ErrorLog(code int) string
}
