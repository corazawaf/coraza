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
// Prevents the matched variable from being logged to the audit log. When the variable that
// matched is a request argument (ARGS, ARGS_GET, ARGS_POST, ARGS_PATH or one of the *_NAMES
// collections), a request header or a response header, every byte of its value is replaced
// with an asterisk, exactly as sanitiseArg, sanitiseRequestHeader and sanitiseResponseHeader
// would. Other variables are ignored, as in ModSecurity v2. ModSecurity v2 only recognises
// ARGS and ARGS_NAMES among the argument collections; Coraza also accepts the GET, POST and
// PATH variants, which always refer to an argument.
//
// Example:
// ```seclang
// # Sanitise any argument that contains the word password in its name
// SecRule ARGS_NAMES "@contains password" "phase:2,id:132,nolog,pass,sanitiseMatched"
// ```
type sanitiseMatchedFn struct{}

func (a *sanitiseMatchedFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}
	return nil
}

func (a *sanitiseMatchedFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	if !tx.(*corazawaf.Transaction).SanitiseMatched() {
		tx.DebugLogger().Debug().
			Int("rule_id", r.ID()).
			Msg("sanitiseMatched ignored: the matched variable is not an argument or a header")
	}
}

func (a *sanitiseMatchedFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func sanitiseMatched() plugintypes.Action {
	return &sanitiseMatchedFn{}
}

var (
	_ plugintypes.Action = &sanitiseMatchedFn{}
	_ ruleActionWrapper  = sanitiseMatched
)
