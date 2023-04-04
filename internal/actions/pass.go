// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type passFn struct{}

func (a *passFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}
	return nil
}

func (a *passFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *passFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeDisruptive
}

func pass() plugintypes.Action {
	return &passFn{}
}

var (
	_ plugintypes.Action = &passFn{}
	_ ruleActionWrapper  = pass
)
