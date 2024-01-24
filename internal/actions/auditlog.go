// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v4/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v4/internal/corazawaf"
)

// Action Group: Non-disruptive
//
// Description:
// Marks the transaction for logging in the audit log.
//
// Example:
// ```
// # The action is explicit if the log is specified.
// SecRule REMOTE_ADDR "^192\.168\.1\.100$" "auditlog,phase:1,id:100,allow"
// ```
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
