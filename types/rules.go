// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package types

// RuleMetadata is used to store rule metadata
// that can be used across packages
type RuleMetadata interface {
	ID() int
	File() string
	Line() int
	Revision() string
	Severity() RuleSeverity
	Version() string
	Tags() []string
	Maturity() int
	Accuracy() int
	Operator() string
	Phase() RulePhase
	Raw() string
	SecMark() string
}

// RuleFilter provides an interface for filtering rules during transaction processing.
// Implementations can define custom logic to determine if a specific rule
// should be ignored for a given transaction based on its metadata.
type RuleFilter interface {
	// ShouldIgnore evaluates the provided RuleMetadata and returns true if the rule
	// should be skipped for the current transaction, false otherwise.
	ShouldIgnore(RuleMetadata) bool
}
