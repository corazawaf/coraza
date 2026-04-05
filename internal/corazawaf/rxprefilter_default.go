// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.rule.rx_prefilter

package corazawaf

// defaultRxPreFilterEnabled enables regex prefiltering feature by default.
// The build tag is meant for testing the feature without needing to set the
// SecRxPreFilter directive. It is used to run the whole test suite with the feature enabled.
const defaultRxPreFilterEnabled = false
