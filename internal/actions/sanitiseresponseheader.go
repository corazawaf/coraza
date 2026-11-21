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
// Prevents a named response header from being logged to the audit log. Each byte of the
// header's value is replaced with an asterisk, in the response headers and in the messages
// of matched rules. Rules still inspect the original value, and the error log is not changed.
//
// Example:
// ```seclang
// SecAction "phase:3,nolog,pass,id:136,sanitiseResponseHeader:Set-Cookie"
// ```
type sanitiseResponseHeaderFn struct {
	name string
}

func (a *sanitiseResponseHeaderFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}
	a.name = data
	return nil
}

func (a *sanitiseResponseHeaderFn) Evaluate(_ plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	tx.(*corazawaf.Transaction).SanitiseResponseHeader(a.name)
}

func (a *sanitiseResponseHeaderFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func sanitiseResponseHeader() plugintypes.Action {
	return &sanitiseResponseHeaderFn{}
}

var (
	_ plugintypes.Action = &sanitiseResponseHeaderFn{}
	_ ruleActionWrapper  = sanitiseResponseHeader
)
