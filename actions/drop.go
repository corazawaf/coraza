// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type dropFn struct{}

func (a *dropFn) Init(r *coraza.Rule, data string) error {
	r.Disruptive = true
	return nil
}

func (a *dropFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	rid := r.ID
	if rid == 0 {
		rid = r.ParentID
	}
	if tx.RuleEngine == types.RuleEngineOn {
		tx.Interruption = &types.Interruption{
			Status: r.DisruptiveStatus,
			RuleID: rid,
			Action: "drop",
		}
	}
}

func (a *dropFn) Type() types.RuleActionType {
	return types.ActionTypeDisruptive
}

func drop() coraza.RuleAction {
	return &dropFn{}
}

var (
	_ coraza.RuleAction = &dropFn{}
	_ ruleActionWrapper = drop
)
