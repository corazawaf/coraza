// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package corazawaf_test provides external black-box tests for the corazawaf package.
// These tests live in a separate test package to allow importing the experimental
// package without creating a circular dependency (experimental → internal/corazawaf).
package corazawaf_test

import (
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// Compile-time assertion: *Transaction must satisfy experimental.StreamingTransaction.
// This test will fail at compile time if the exported StreamingTransaction interface
// (including ProcessRequestBodyFromStream and ProcessResponseBodyFromStream) diverges
// from the concrete *Transaction implementation, catching interface drift early.
var _ experimental.StreamingTransaction = corazawaf.NewWAF().NewTransaction()
