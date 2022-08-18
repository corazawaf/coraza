// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type chainFn struct{}

func (a *chainFn) Init(r *coraza.Rule, b1 string) error {
	r.HasChain = true
	return nil
}

func (a *chainFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *chainFn) Type() types.RuleActionType {
	return types.ActionTypeFlow
}

func chain() coraza.RuleAction {
	return &chainFn{}
}

var (
	_ coraza.RuleAction = &chainFn{}
	_ ruleActionWrapper = chain
)
