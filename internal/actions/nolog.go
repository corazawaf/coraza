// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/redwanghb/coraza/v3/experimental/plugins/plugintypes"
	"github.com/redwanghb/coraza/v3/internal/corazawaf"
)

// Action Group: Non-disruptive
//
// Description:
// Prevents rule matches from appearing in both error and audit logs.
// Although nolog implies noauditlog, you can override the former by using `nolog,auditlog`.
//
// Example:
// ```
// SecRule REQUEST_HEADERS:User-Agent "@streq Test" "allow,nolog,id:121"
// ```
type nologFn struct{}

func (a *nologFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}

	r.(*corazawaf.Rule).Log = false
	r.(*corazawaf.Rule).Audit = false
	return nil
}

func (a *nologFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *nologFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func nolog() plugintypes.Action {
	return &nologFn{}
}

var (
	_ plugintypes.Action = &nologFn{}
	_ ruleActionWrapper  = nolog
)
