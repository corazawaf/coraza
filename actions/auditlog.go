// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type auditlogFn struct{}

func (a *auditlogFn) Init(r rules.RuleMetadata, _ string) error {
	// TODO(jcchavezs): Shall we return an error if data is not empty?
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).Audit = true
	return nil
}

func (a *auditlogFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {}

func (a *auditlogFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func auditlog() rules.Action {
	return &auditlogFn{}
}

var (
	_ rules.Action      = (*auditlogFn)(nil)
	_ ruleActionWrapper = auditlog
)
