// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type verFn struct{}

func (a *verFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}
	r.(*corazawaf.Rule).Version_ = data
	return nil
}

func (a *verFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *verFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeMetadata
}

func ver() plugintypes.Action {
	return &verFn{}
}

var (
	_ plugintypes.Action = &verFn{}
	_ ruleActionWrapper  = ver
)
