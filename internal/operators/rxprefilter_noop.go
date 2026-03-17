// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.rule.rx_prefilter

package operators

// minMatchLength is a no-op when the rx_prefilter build tag is not set.
// Enable with: go build -tags coraza.rule.rx_prefilter
func minMatchLength(_ string) int { return 0 }

// prefilterFunc is a no-op when the rx_prefilter build tag is not set.
// Enable with: go build -tags coraza.rule.rx_prefilter
func prefilterFunc(_ string) func(string) bool { return nil }
