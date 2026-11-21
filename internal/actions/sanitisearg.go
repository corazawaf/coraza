// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// Action Group: Non-disruptive
//
// Description:
// Prevents sensitive request parameter data from being logged to the audit log.
// Each byte of the named parameter's value is replaced with an asterisk, wherever the
// value appears in the audit log: the request line, the request body, the arguments and
// the messages of matched rules. Parameter names are compared case-insensitively, as in
// ModSecurity v2. Rules still inspect the original value, and the error log is not changed.
//
// Example:
// ```seclang
// # Never log passwords
// SecAction "nolog,phase:2,id:131,sanitiseArg:password,sanitiseArg:newPassword,sanitiseArg:oldPassword"
// ```
type sanitiseArgFn struct {
	name string
}

func (a *sanitiseArgFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}
	a.name = data
	return nil
}

func (a *sanitiseArgFn) Evaluate(_ plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	tx.(*corazawaf.Transaction).SanitiseArg(a.name)
}

func (a *sanitiseArgFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func sanitiseArg() plugintypes.Action {
	return &sanitiseArgFn{}
}

var (
	_ plugintypes.Action = &sanitiseArgFn{}
	_ ruleActionWrapper  = sanitiseArg
)
