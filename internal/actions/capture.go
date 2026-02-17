// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// Action Group: Non-disruptive
//
// Description:
// > This action is being forced by now, it might be reused in the future.
//
// When used together with the regular expression operator `@rx`,
// `capture` creates a copy of the regular expression and places them into the transaction variable collection.
// Up to 10 captures will be copied on a successful pattern match, each with a name consisting of a digit from 0 to 9.
// The `TX.0` variable always contains the entire area that the regular expression matched.
// All the other variables contain the captured values, in the order in which the capturing parentheses appear in the regular expression.
//
// Example:
// ```
//
//	  SecRule REQUEST_BODY "^username=(\w{25,})" "phase:2,capture,t:none,chain,id:105"
//		   SecRule TX:1 "(?:(?:a(dmin|nonymous)))"
//
// ```
type captureFn struct{}

func (a *captureFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}

	r.(*corazawaf.Rule).Capture = true
	return nil
}

func (a *captureFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *captureFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func capture() plugintypes.Action {
	return &captureFn{}
}

var (
	_ plugintypes.Action = &captureFn{}
	_ ruleActionWrapper  = capture
)
