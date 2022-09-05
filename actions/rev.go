// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type revFn struct {
}

func (a *revFn) Init(r *corazawaf.Rule, data string) error {
	r.Rev = data
	return nil
}

func (a *revFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// Not evaluated
}

func (a *revFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func rev() corazawaf.RuleAction {
	return &revFn{}
}

var (
	_ corazawaf.RuleAction = &revFn{}
	_ ruleActionWrapper    = rev
)
