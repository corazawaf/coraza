// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.rule.rx_prefilter

package corazawaf

// defaultRxPreFilterEnabled is true when the coraza.rule.rx_prefilter build tag
// is set so that the entire test suite (and any deployment built with the tag)
// exercises the prefilter path without requiring an explicit SecRxPreFilter On
// directive. The directive can still override this per WAF instance.
const defaultRxPreFilterEnabled = true
