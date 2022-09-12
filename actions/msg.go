// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
)

type msgFn struct {
}

func (a *msgFn) Init(r rules.Rule, data string) error {
	data = utils.RemoveQuotes(data)
	msg, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).Msg = msg
	return nil
}

func (a *msgFn) Evaluate(r rules.Rule, tx rules.TransactionState) {
	// Not evaluated
}

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
