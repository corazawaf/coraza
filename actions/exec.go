// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type execFn struct {
}

func (a *execFn) Init(r *coraza.Rule, data string) error {
	return nil
}

func (a *execFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not implemented
}

func (a *execFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func exec() coraza.RuleAction {
	return &execFn{}
}

var (
	_ coraza.RuleAction = &execFn{}
	_ ruleActionWrapper = exec
)
