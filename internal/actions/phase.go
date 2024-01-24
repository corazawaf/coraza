// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v4/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v4/internal/corazawaf"
	"github.com/corazawaf/coraza/v4/types"
)

// Action Group: Metadata
//
// Description:
// Places the rule or chain into one of five available processing phases.
// It can also be used in `SecDefaultAction` to establish the rule defaults.
//
// Besides, There are aliases for some phase numbers:
// - 2 (request)
// - 4 (response)
// - 5 (logging)
//
// > Warning: Keep in mind that the variable used in the rule may not be available if specifying the incorrect phase.
// > This could lead to a false negative situation where your variable and operator may be correct,
// > but it misses malicious data because you specified the wrong phase.
//
// Example:
// ```
// # Initialize IP address tracking in phase 1
// SecAction phase:1,nolog,pass,id:126,initcol:IP=%{REMOTE_ADDR}
//
// # Example of using phase alias
// SecRule REQUEST_HEADERS:User-Agent "Test" "phase:request,log,deny,id:127"
// ```
type phaseFn struct{}

func (a *phaseFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

	p, err := types.ParseRulePhase(data)
	if err != nil {
		return err
	}
	r.(*corazawaf.Rule).Phase_ = p
	return nil
}

func (a *phaseFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *phaseFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeMetadata
}

func phase() plugintypes.Action {
	return &phaseFn{}
}

var (
	_ plugintypes.Action = &phaseFn{}
	_ ruleActionWrapper  = phase
)
