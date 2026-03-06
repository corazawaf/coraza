// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugintypes

import "io/fs"

// Memoizer caches the result of expensive function calls by key.
// Implementations must be safe for concurrent use.
type Memoizer interface {
	Do(key string, fn func() (any, error)) (any, error)
}

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

	// Memoizer caches expensive compilations (regex, aho-corasick).
	Memoizer Memoizer
}

// Operator interface is used to define rule @operators
type Operator interface {
	// Evaluate is used during the rule evaluation,
	// it returns true if the operator succeeded against
	// the input data for the transaction
	Evaluate(TransactionState, string) bool
}

type OperatorFactory func(options OperatorOptions) (Operator, error)
