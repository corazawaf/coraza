// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type noauditlogFn struct {
}

func (a *noauditlogFn) Init(r *corazawaf.Rule, data string) error {
	r.Audit = false
	return nil
}

func (a *noauditlogFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
}

func (a *noauditlogFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func noauditlog() corazawaf.RuleAction {
	return &noauditlogFn{}
}

var (
	_ corazawaf.RuleAction = &noauditlogFn{}
	_ ruleActionWrapper    = noauditlog
)
