// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
)

type msgFn struct{}

func (a *msgFn) Init(r rules.RuleMetadata, data string) error {
	data = utils.MaybeRemoveQuotes(data)
	if len(data) == 0 {
		return ErrMissingArguments
	}

	msg, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	r.(*corazawaf.Rule).Msg = msg
	return nil
}

func (a *msgFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {}

func (a *msgFn) Type() rules.ActionType {
	return rules.ActionTypeMetadata
}

func msg() rules.Action {
	return &msgFn{}
}

var (
	_ rules.Action      = &msgFn{}
	_ ruleActionWrapper = msg
)
