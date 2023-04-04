// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazatypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// 0 nothing, 1 phase, 2 request
type allowFn struct {
	allow corazatypes.AllowType
}

func (a *allowFn) Init(_ plugintypes.RuleMetadata, data string) error {
	switch data {
	case "phase":
		a.allow = corazatypes.AllowTypePhase // skip current phase
	case "request":
		a.allow = corazatypes.AllowTypeRequest // skip phases until RESPONSE_HEADERS
	case "":
		a.allow = corazatypes.AllowTypeAll // skip all phases
	default:
		return fmt.Errorf("invalid argument %q", data)
	}
	return nil
}

// Evaluate Allow has the following rules:
//
// Example: `SecRule REMOTE_ADDR "^192\.168\.1\.100$" "phase:1,id:95,nolog,allow"`
//
//   - If used one its own, like in the example above, allow will affect the entire transaction,
//     stopping processing of the current phase but also skipping over all other phases apart from the logging phase.
//     (The logging phase is special; it is designed to always execute.)
//   - If used with parameter "phase", allow will cause the engine to stop processing the current phase.
//     Other phases will continue as normal.
//   - If used with parameter "request", allow will cause the engine to stop processing the current phase.
//     The next phase to be processed will be phase types.PhaseResponseHeaders.
func (a *allowFn) Evaluate(r plugintypes.RuleMetadata, txS plugintypes.TransactionState) {
	tx := txS.(*corazawaf.Transaction)
	tx.AllowType = a.allow
}

func (a *allowFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeDisruptive
}

func allow() plugintypes.Action {
	return &allowFn{}
}

var (
	_ plugintypes.Action = (*allowFn)(nil)
	_ ruleActionWrapper  = allow
)
