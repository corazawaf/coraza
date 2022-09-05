// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type chainFn struct{}

func (a *chainFn) Init(r *corazawaf.Rule, b1 string) error {
	r.HasChain = true
	return nil
}

func (a *chainFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// Not evaluated
}

func (a *chainFn) Type() types.RuleActionType {
	return types.ActionTypeFlow
}

func chain() corazawaf.RuleAction {
	return &chainFn{}
}

var (
	_ corazawaf.RuleAction = &chainFn{}
	_ ruleActionWrapper    = chain
)
