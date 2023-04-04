// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type expirevarFn struct{}

func (a *expirevarFn) Init(_ plugintypes.RuleMetadata, data string) error {
	return nil
}

func (a *expirevarFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	// Not supported
	tx.DebugLogger().Warn().Int("rule_id", r.ID()).Msg("Expirevar was used but it's not supported")
}

func (a *expirevarFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func expirevar() plugintypes.Action {
	return &expirevarFn{}
}

var (
	_ plugintypes.Action = &expirevarFn{}
	_ ruleActionWrapper  = expirevar
)
