// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/corazawaf/coraza/v3/types"
)

type dropFn struct{}

func (a *dropFn) Init(r rules.Rule, data string) error {
	return nil
}

func (a *dropFn) Evaluate(r rules.Rule, tx rules.TransactionState) {
	rid := r.GetID()
	if rid == 0 {
		rid = r.GetParentID()
	}
	tx.Interrupt(&types.Interruption{
		Status: r.Status(),
		RuleID: rid,
		Action: "drop",
	})
}

func (a *dropFn) Type() rules.ActionType {
	return rules.ActionTypeDisruptive
}

func drop() rules.Action {
	return &dropFn{}
}

var (
	_ rules.Action      = &dropFn{}
	_ ruleActionWrapper = drop
)
