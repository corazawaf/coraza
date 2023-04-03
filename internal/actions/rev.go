// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type revFn struct{}

func (a *revFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}
	r.(*corazawaf.Rule).Rev_ = data
	return nil
}

func (a *revFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *revFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeMetadata
}

func rev() plugintypes.Action {
	return &revFn{}
}

var (
	_ plugintypes.Action = &revFn{}
	_ ruleActionWrapper  = rev
)
