// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type logFn struct{}

func (a *logFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}

	r.(*corazawaf.Rule).Log = true
	r.(*corazawaf.Rule).Audit = true
	return nil
}

func (a *logFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *logFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func log() plugintypes.Action {
	return &logFn{}
}

var (
	_ plugintypes.Action = &logFn{}
	_ ruleActionWrapper  = log
)
