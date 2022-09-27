// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
)

type msgFn struct {
}

func (a *msgFn) Init(r *coraza.Rule, data string) error {
	data = utils.MaybeRemoveQuotes(data)
	msg, err := coraza.NewMacro(data)
	if err != nil {
		return err
	}
	r.Msg = *msg
	return nil
}

func (a *msgFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *msgFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func msg() coraza.RuleAction {
	return &msgFn{}
}

var (
	_ coraza.RuleAction = &msgFn{}
	_ ruleActionWrapper = msg
)
