// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type tagFn struct {
}

func (a *tagFn) Init(r *corazawaf.Rule, data string) error {
	r.Tags = append(r.Tags, data)
	return nil
}

func (a *tagFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// Not evaluated
}

func (a *tagFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func tag() corazawaf.RuleAction {
	return &tagFn{}
}

var (
	_ corazawaf.RuleAction = &tagFn{}
	_ ruleActionWrapper    = tag
)
