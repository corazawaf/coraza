// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type chainFn struct{}

func (a *chainFn) Init(r rules.RuleInfo, b1 string) error {
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).HasChain = true
	return nil
}

func (a *chainFn) Evaluate(r rules.RuleInfo, tx rules.TransactionState) {
	// Not evaluated
}

func (a *chainFn) Type() rules.ActionType {
	return rules.ActionTypeFlow
}

func chain() rules.Action {
	return &chainFn{}
}

var (
	_ rules.Action      = &chainFn{}
	_ ruleActionWrapper = chain
)
