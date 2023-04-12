// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type tagFn struct{}

func (a *tagFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}
	r.(*corazawaf.Rule).Tags_ = append(r.(*corazawaf.Rule).Tags_, data)
	return nil
}

func (a *tagFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *tagFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeMetadata
}

func tag() plugintypes.Action {
	return &tagFn{}
}

var (
	_ plugintypes.Action = &tagFn{}
	_ ruleActionWrapper  = tag
)
