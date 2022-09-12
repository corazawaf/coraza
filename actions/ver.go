// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type verFn struct {
}

func (a *verFn) Init(r rules.Rule, data string) error {
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).Version = data
	return nil
}

func (a *verFn) Evaluate(r rules.Rule, tx rules.TransactionState) {
	// Not evaluated
}

func (a *verFn) Type() rules.ActionType {
	return rules.ActionTypeMetadata
}

func ver() rules.Action {
	return &verFn{}
}

var (
	_ rules.Action      = &verFn{}
	_ ruleActionWrapper = ver
)
