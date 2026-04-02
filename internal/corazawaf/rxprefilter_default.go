// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.rule.rx_prefilter

package corazawaf

// The feature is always compiled, and by default disabled. It can be set via SecRxPreFilter.
// This build tag is used to enable the feature by default for testing, being able to run the whole
// test suite with the feature enabled.
const defaultRxPreFilterEnabled = false
