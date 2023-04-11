// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type execFn struct{}

func (a *execFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}
	return nil
}

func (a *execFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *execFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func exec() plugintypes.Action {
	return &execFn{}
}

var (
	_ plugintypes.Action = &execFn{}
	_ ruleActionWrapper  = exec
)
