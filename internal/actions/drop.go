// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

type dropFn struct{}

func (a *dropFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}
	return nil
}

func (a *dropFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	rid := r.ID()
	if rid == noID {
		rid = r.ParentID()
	}
	tx.Interrupt(&types.Interruption{
		Status: r.Status(),
		RuleID: rid,
		Action: "drop",
	})
}

func (a *dropFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeDisruptive
}

func drop() plugintypes.Action {
	return &dropFn{}
}

var (
	_ plugintypes.Action = &dropFn{}
	_ ruleActionWrapper  = drop
)
