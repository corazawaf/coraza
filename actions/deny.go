// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type denyFn struct{}

func (a *denyFn) Init(r *corazawaf.Rule, data string) error {
	r.Disruptive = true
	return nil
}

func (a *denyFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	rid := r.ID
	if rid == 0 {
		rid = r.ParentID
	}
	if tx.RuleEngine == types.RuleEngineOn {
		tx.Interruption = &types.Interruption{
			Status: r.DisruptiveStatus,
			RuleID: rid,
			Action: "deny",
		}
	}
}

func (a *denyFn) Type() types.RuleActionType {
	return types.ActionTypeDisruptive
}

func deny() corazawaf.RuleAction {
	return &denyFn{}
}

var (
	_ corazawaf.RuleAction = &denyFn{}
	_ ruleActionWrapper    = deny
)
