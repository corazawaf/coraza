// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type auditlogFn struct{}

func (a *auditlogFn) Init(r *coraza.Rule, data string) error {
	r.Audit = true
	return nil
}

func (a *auditlogFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Nothing here
}

func (a *auditlogFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func auditlog() coraza.RuleAction {
	return &auditlogFn{}
}

var (
	_ coraza.RuleAction = (*auditlogFn)(nil)
	_ ruleActionWrapper = auditlog
)
