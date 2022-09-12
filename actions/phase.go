// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/corazawaf/coraza/v3/types"
)

type phaseFn struct{}

func (a *phaseFn) Init(r rules.Rule, data string) error {
	p, err := types.ParseRulePhase(data)
	if err != nil {
		return err
	}
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).Phase = p
	return nil
}

func (a *phaseFn) Evaluate(r rules.Rule, tx rules.TransactionState) {
	// Not evaluated
}

func (a *phaseFn) Type() rules.ActionType {
	return rules.ActionTypeMetadata
}

func phase() rules.Action {
	return &phaseFn{}
}

var (
	_ rules.Action      = &phaseFn{}
	_ ruleActionWrapper = phase
)
