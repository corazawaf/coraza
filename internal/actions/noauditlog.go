// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type noauditlogFn struct{}

func (a *noauditlogFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}

	r.(*corazawaf.Rule).Audit = false
	return nil
}

func (a *noauditlogFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *noauditlogFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func noauditlog() plugintypes.Action {
	return &noauditlogFn{}
}

var (
	_ plugintypes.Action = &noauditlogFn{}
	_ ruleActionWrapper  = noauditlog
)
