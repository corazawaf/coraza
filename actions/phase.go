// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type phaseFn struct{}

func (a *phaseFn) Init(r *corazawaf.Rule, data string) error {
	p, err := types.ParseRulePhase(data)
	if err != nil {
		return err
	}
	r.Phase = p
	return nil
}

func (a *phaseFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// Not evaluated
}

func (a *phaseFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func phase() corazawaf.RuleAction {
	return &phaseFn{}
}

var (
	_ corazawaf.RuleAction = &phaseFn{}
	_ ruleActionWrapper    = phase
)
