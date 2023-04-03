// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type multimatchFn struct{}

func (a *multimatchFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}
	r.(*corazawaf.Rule).MultiMatch = true
	return nil
}

func (a *multimatchFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *multimatchFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func multimatch() plugintypes.Action {
	return &multimatchFn{}
}

var (
	_ plugintypes.Action = &multimatchFn{}
	_ ruleActionWrapper  = multimatch
)
