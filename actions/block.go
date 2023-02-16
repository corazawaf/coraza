// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/rules"
)

type blockFn struct{}

func (a *blockFn) Init(_ rules.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}

	return nil
}

func (a *blockFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {
	// This should never run
	// TODO(jcchavezs): check if we return a panic
}

func (a *blockFn) Type() rules.ActionType {
	return rules.ActionTypeDisruptive
}

func block() rules.Action {
	return &blockFn{}
}

var (
	_ rules.Action      = &blockFn{}
	_ ruleActionWrapper = block
)
