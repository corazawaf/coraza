// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.rule.mandatory_rule_id_check

package corazawaf

var shouldDoMandatoryRuleIdCheck = false
