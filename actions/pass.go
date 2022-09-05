// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type passFn struct {
}

func (a *passFn) Init(r *corazawaf.Rule, data string) error {
	return nil
}

func (a *passFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// Not evaluated
}

func (a *passFn) Type() types.RuleActionType {
	return types.ActionTypeDisruptive
}

func pass() corazawaf.RuleAction {
	return &passFn{}
}

var (
	_ corazawaf.RuleAction = &passFn{}
	_ ruleActionWrapper    = pass
)
