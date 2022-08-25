// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type passFn struct {
}

func (a *passFn) Init(r *coraza.Rule, data string) error {
	return nil
}

func (a *passFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *passFn) Type() types.RuleActionType {
	return types.ActionTypeDisruptive
}

func pass() coraza.RuleAction {
	return &passFn{}
}

var (
	_ coraza.RuleAction = &passFn{}
	_ ruleActionWrapper = pass
)
