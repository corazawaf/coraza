// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type chainFn struct{}

func (a *chainFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}

	r.(*corazawaf.Rule).HasChain = true
	return nil
}

func (a *chainFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *chainFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeFlow
}

func chain() plugintypes.Action {
	return &chainFn{}
}

var (
	_ plugintypes.Action = &chainFn{}
	_ ruleActionWrapper  = chain
)
