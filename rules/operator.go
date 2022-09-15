// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import "io/fs"

// RuleOperatorOptions is used to store the options for a rule operator
type RuleOperatorOptions struct {
	// Arguments is used to store the operator args
	Arguments string

	// Path is used to store a list of possible data paths
	Path []string

	// Root is the root to resolve Path from.
	Root fs.FS

	// Datasets contains input datasets or dictionaries
	Datasets map[string][]string
}

// RuleOperator interface is used to define rule @operators
type RuleOperator interface {
	// Init is used during compilation to setup and cache
	// the operator
	Init(RuleOperatorOptions) error
	// Evaluate is used during the rule evaluation,
	// it returns true if the operator succeeded against
	// the input data for the transaction
	Evaluate(TransactionState, string) bool
}
