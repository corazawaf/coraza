// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/corazawaf/coraza/v3/types"
)

type redirectFn struct {
	target string
}

func (a *redirectFn) Init(_ rules.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

	a.target = data
	return nil
}

func (a *redirectFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	rid := r.ID()
	if rid == 0 {
		rid = r.ParentID()
	}
	tx.Interrupt(&types.Interruption{
		Status: r.Status(),
		RuleID: rid,
		Action: "redirect",
		Data:   a.target,
	})
}

func (a *redirectFn) Type() rules.ActionType {
	return rules.ActionTypeDisruptive
}

func redirect() rules.Action {
	return &redirectFn{}
}

var (
	_ rules.Action      = &redirectFn{}
	_ ruleActionWrapper = redirect
)
