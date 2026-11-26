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
// Prevents a named request header from being logged to the audit log. Each byte of the
// header's value is replaced with an asterisk, in the request headers and in the messages
// of matched rules. Rules still inspect the original value, and the error log is not changed.
//
// Example:
// ```seclang
// SecAction "phase:1,nolog,pass,id:135,sanitiseRequestHeader:Authorization"
// ```
type sanitiseRequestHeaderFn struct {
	name string
}

func (a *sanitiseRequestHeaderFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}
	a.name = data
	return nil
}

func (a *sanitiseRequestHeaderFn) Evaluate(_ plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	tx.(*corazawaf.Transaction).SanitiseRequestHeader(a.name)
}

func (a *sanitiseRequestHeaderFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func sanitiseRequestHeader() plugintypes.Action {
	return &sanitiseRequestHeaderFn{}
}

var (
	_ plugintypes.Action = &sanitiseRequestHeaderFn{}
	_ ruleActionWrapper  = sanitiseRequestHeader
)
