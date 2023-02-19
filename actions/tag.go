// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type tagFn struct{}

func (a *tagFn) Init(r rules.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}
	r.(*corazawaf.Rule).Tags_ = append(r.(*corazawaf.Rule).Tags_, data)
	return nil
}

func (a *tagFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {}

func (a *tagFn) Type() rules.ActionType {
	return rules.ActionTypeMetadata
}

func tag() rules.Action {
	return &tagFn{}
}

var (
	_ rules.Action      = &tagFn{}
	_ ruleActionWrapper = tag
)
