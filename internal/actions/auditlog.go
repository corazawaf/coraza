// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type auditlogFn struct{}

func (a *auditlogFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}

	r.(*corazawaf.Rule).Audit = true
	return nil
}

func (a *auditlogFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *auditlogFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func auditlog() plugintypes.Action {
	return &auditlogFn{}
}

var (
	_ plugintypes.Action = (*auditlogFn)(nil)
	_ ruleActionWrapper  = auditlog
)
