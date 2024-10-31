// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// Action Group: Disruptive
//
// Description:
// Intercepts transaction by issuing an external (client-visible) redirection to the given location.
// If the status action is presented on the same rule,  and its value can be used for a redirection
// (supported redirection codes: 301, 302, 303, 307) the value will be used for the redirection status code.
// Otherwise, status code 302 will be used.
//
// Example:
// ```
// SecRule REQUEST_HEADERS:User-Agent "@streq Test" "phase:1,id:130,log,redirect:http://www.example.com/failed.html"
// ```
type redirectFn struct {
	target string
}

func (a *redirectFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

	a.target = data
	return nil
}

func (a *redirectFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	status := 302 // default status code for redirection
	rid := r.ID()
	if rid == noID {
		rid = r.ParentID()
	}
	rstatus := r.Status()
	if rstatus == 301 || rstatus == 302 || rstatus == 303 || rstatus == 307 {
		status = rstatus
	}
	tx.Interrupt(&types.Interruption{
		Status: status,
		RuleID: rid,
		Action: "redirect",
		Data:   a.target,
	})
}

func (a *redirectFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeDisruptive
}

func redirect() plugintypes.Action {
	return &redirectFn{}
}

var (
	_ plugintypes.Action = &redirectFn{}
	_ ruleActionWrapper  = redirect
)
