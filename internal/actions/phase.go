// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type phaseFn struct{}

func (a *phaseFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

	p, err := types.ParseRulePhase(data)
	if err != nil {
		return err
	}
	r.(*corazawaf.Rule).Phase_ = p
	return nil
}

func (a *phaseFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *phaseFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeMetadata
}

func phase() plugintypes.Action {
	return &phaseFn{}
}

var (
	_ plugintypes.Action = &phaseFn{}
	_ ruleActionWrapper  = phase
)
