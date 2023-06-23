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
// If the status action is presented on the same rule,
// and its value can be used for a redirection (i.e., one of the following: 301, 302, 303, or 307),
// the value will be used for the redirection status code. Otherwise, status code 302 will be used.
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
	rid := r.ID()
	if rid == noID {
		rid = r.ParentID()
	}
	tx.Interrupt(&types.Interruption{
		Status: r.Status(),
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
