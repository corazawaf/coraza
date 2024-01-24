// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v4/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v4/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v4/internal/corazawaf"
	utils "github.com/corazawaf/coraza/v4/internal/strings"
)

// Action Group: Metadata
//
// Description:
// Assigns a custom message to the rule or chain in which it appears, and the message will be logged along with every alert.
// Noted that the msg information appears in the error and/or audit log files and is not sent back to the client in response headers.
//
// Example:
// ```
// SecRule &REQUEST_HEADERS:Host "@eq 0" "log,id:60008,severity:2,msg:'Request Missing a Host Header'"
// ```
type msgFn struct{}

func (a *msgFn) Init(r plugintypes.RuleMetadata, data string) error {
	data = utils.MaybeRemoveQuotes(data)
	if len(data) == 0 {
		return ErrMissingArguments
	}

	msg, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	r.(*corazawaf.Rule).Msg = msg
	return nil
}

func (a *msgFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *msgFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeMetadata
}

func msg() plugintypes.Action {
	return &msgFn{}
}

var (
	_ plugintypes.Action = &msgFn{}
	_ ruleActionWrapper  = msg
)
