// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type blockFn struct{}

func (a *blockFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}

	return nil
}

func (a *blockFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {
	// This should never run
	// TODO(jcchavezs): check if we return a panic
}

func (a *blockFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeDisruptive
}

func block() plugintypes.Action {
	return &blockFn{}
}

var (
	_ plugintypes.Action = &blockFn{}
	_ ruleActionWrapper  = block
)
