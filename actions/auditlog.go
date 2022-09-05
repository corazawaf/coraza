// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type auditlogFn struct{}

func (a *auditlogFn) Init(r *corazawaf.Rule, data string) error {
	r.Audit = true
	return nil
}

func (a *auditlogFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// Nothing here
}

func (a *auditlogFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func auditlog() corazawaf.RuleAction {
	return &auditlogFn{}
}

var (
	_ corazawaf.RuleAction = (*auditlogFn)(nil)
	_ ruleActionWrapper    = auditlog
)
