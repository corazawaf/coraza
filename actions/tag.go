// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type tagFn struct {
}

func (a *tagFn) Init(r rules.RuleInfo, data string) error {
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).Tags = append(r.(*corazawaf.Rule).Tags, data)
	return nil
}

func (a *tagFn) Evaluate(r rules.RuleInfo, tx rules.TransactionState) {
	// Not evaluated
}

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
