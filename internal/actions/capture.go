// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type captureFn struct{}

func (a *captureFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}

	r.(*corazawaf.Rule).Capture = true
	return nil
}

func (a *captureFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *captureFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func capture() plugintypes.Action {
	return &captureFn{}
}

var (
	_ plugintypes.Action = &captureFn{}
	_ ruleActionWrapper  = capture
)
