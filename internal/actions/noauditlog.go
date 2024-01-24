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
// Indicates that a successful match of the rule should not be used as criteria to determine whether the transaction should be logged to the audit log.
// If the `SecAuditEngine` is set to `On`, all of the transactions will be logged.
// If it is set to `RelevantOnly`, you can control the logging with the noauditlog action.
// Action `noauditlog` affects only on the current rule. If you prevent audit logging in one rule only,
// a match in another rule will still cause audit logging to take place.
// If you want to prevent audit logging from taking place, regardless of whether any rule matches, use `ctl:auditEngine=Off`.
//
// Example:
// ```
// SecRule REQUEST_HEADERS:User-Agent "@streq Test" "allow,noauditlog,id:120"
// ```
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
