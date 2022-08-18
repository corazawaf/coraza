// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type tagFn struct {
}

func (a *tagFn) Init(r *coraza.Rule, data string) error {
	r.Tags = append(r.Tags, data)
	return nil
}

func (a *tagFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *tagFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func tag() coraza.RuleAction {
	return &tagFn{}
}

var (
	_ coraza.RuleAction = &tagFn{}
	_ ruleActionWrapper = tag
)
