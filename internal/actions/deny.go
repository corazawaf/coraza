// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"net/http"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// Action Group: Disruptive
//
// Description:
// Stops rule processing and intercepts transaction.
// If status action is not used, deny action defaults to status 403.
//
// Example:
// ```seclang
// SecRule REQUEST_HEADERS:User-Agent "nikto" "log,deny,id:107,msg:'Nikto Scanners Identified'"
// ```
type denyFn struct{}

func (a *denyFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}
	return nil
}

const noID = 0
const noStatus = 0

// statusOrForbidden returns the rule's status, or 403 when the rule has no
// status action. deny and drop share this default, as in ModSecurity.
func statusOrForbidden(r plugintypes.RuleMetadata) int {
	if status := r.Status(); status != noStatus {
		return status
	}
	return http.StatusForbidden
}

func (a *denyFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	rid := r.ID()
	if rid == noID {
		rid = r.ParentID()
	}
	tx.Interrupt(&types.Interruption{
		Status: statusOrForbidden(r),
		RuleID: rid,
		Action: "deny",
	})
}

func (a *denyFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeDisruptive
}

func deny() plugintypes.Action {
	return &denyFn{}
}

var (
	_ plugintypes.Action = &denyFn{}
	_ ruleActionWrapper  = deny
)
