// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// This package defines shared types for the rulefilter package.

package rftypes

import "github.com/corazawaf/coraza/v3/types"

// RuleFilter provides an interface for filtering rules during transaction processing.
// Implementations can define custom logic to determine if a specific rule
// should be ignored for a given transaction based on its metadata.
type RuleFilter interface {
	// ShouldIgnore evaluates the provided RuleMetadata and returns true if the rule
	// should be skipped for the current transaction, false otherwise.
	ShouldIgnore(types.RuleMetadata) bool
}
