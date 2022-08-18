// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type revFn struct {
}

func (a *revFn) Init(r *coraza.Rule, data string) error {
	r.Rev = data
	return nil
}

func (a *revFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *revFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func rev() coraza.RuleAction {
	return &revFn{}
}

var (
	_ coraza.RuleAction = &revFn{}
	_ ruleActionWrapper = rev
)
