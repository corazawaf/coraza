// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugintypes

import "io/fs"

// OperatorOptions is used to store the options for a rule operator
type OperatorOptions struct {
	// Arguments is used to store the operator args
	Arguments string

	// Path is used to store a list of possible data paths
	Path []string

	// Root is the root to resolve Path from.
	Root fs.FS

	// Datasets contains input datasets or dictionaries
	Datasets map[string][]string
}

// Operator interface is used to define rule @operators
type Operator interface {
	// Evaluate is used during the rule evaluation,
	// it returns true if the operator succeeded against
	// the input data for the transaction
	Evaluate(TransactionState, string) bool
}

type OperatorFactory func(options OperatorOptions) (Operator, error)
