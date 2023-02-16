// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type auditlogFn struct{}

func (a *auditlogFn) Init(r rules.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}

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
