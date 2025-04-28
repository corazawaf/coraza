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
