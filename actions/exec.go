// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type execFn struct {
}

func (a *execFn) Init(r *corazawaf.Rule, data string) error {
	return nil
}

func (a *execFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// Not implemented
}

func (a *execFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func exec() corazawaf.RuleAction {
	return &execFn{}
}

var (
	_ corazawaf.RuleAction = &execFn{}
	_ ruleActionWrapper    = exec
)
