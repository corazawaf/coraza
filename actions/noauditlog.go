// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type noauditlogFn struct {
}

func (a *noauditlogFn) Init(r *coraza.Rule, data string) error {
	r.Audit = false
	return nil
}

func (a *noauditlogFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
}

func (a *noauditlogFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func noauditlog() coraza.RuleAction {
	return &noauditlogFn{}
}

var (
	_ coraza.RuleAction = &noauditlogFn{}
	_ ruleActionWrapper = noauditlog
)
