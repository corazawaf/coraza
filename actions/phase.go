// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type phaseFn struct{}

func (a *phaseFn) Init(r *coraza.Rule, data string) error {
	p, err := types.ParseRulePhase(data)
	if err != nil {
		return err
	}
	r.Phase = p
	return nil
}

func (a *phaseFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *phaseFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func phase() coraza.RuleAction {
	return &phaseFn{}
}

var (
	_ coraza.RuleAction = &phaseFn{}
	_ ruleActionWrapper = phase
)
