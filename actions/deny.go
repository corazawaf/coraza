// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/corazawaf/coraza/v3/types"
)

type denyFn struct{}

func (a *denyFn) Init(r rules.RuleMetadata, data string) error {
	return nil
}

func (a *denyFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	rid := r.GetID()
	if rid == 0 {
		rid = r.GetParentID()
	}
	tx.Interrupt(&types.Interruption{
		Status: r.Status(),
		RuleID: rid,
		Action: "deny",
	})
}

func (a *denyFn) Type() rules.ActionType {
	return rules.ActionTypeDisruptive
}

func deny() rules.Action {
	return &denyFn{}
}

var (
	_ rules.Action      = &denyFn{}
	_ ruleActionWrapper = deny
)
