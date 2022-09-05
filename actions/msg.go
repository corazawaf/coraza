// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
)

type msgFn struct {
}

func (a *msgFn) Init(r *corazawaf.Rule, data string) error {
	data = utils.RemoveQuotes(data)
	msg, err := corazawaf.NewMacro(data)
	if err != nil {
		return err
	}
	r.Msg = *msg
	return nil
}

func (a *msgFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// Not evaluated
}

func (a *msgFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func msg() corazawaf.RuleAction {
	return &msgFn{}
}

var (
	_ corazawaf.RuleAction = &msgFn{}
	_ ruleActionWrapper    = msg
)
