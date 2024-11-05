// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package rule

type RuleID string

// Rule represents a WAF rule, which can be serialized from and to seclang or other languages
type Rule struct {
	ID RuleID
}
