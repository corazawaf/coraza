// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/rules"
)

// 0 nothing, 1 phase, 2 request
type allowFn struct {
	allow int
}

func (a *allowFn) Init(r rules.RuleMetadata, b1 string) error {
	switch b1 {
	case "phase":
		a.allow = 2 // skip current phase
	case "request":
		a.allow = 3 // skip phases until RESPONSE_HEADERS
	case "":
		a.allow = 1 // skip all phases
	default:
		return fmt.Errorf("invalid argument %s for allow", b1)
	}
	return nil
}

func (a *allowFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	// TODO implement this:
	/*
		if a.allow == 1 {
			tx.RuleEngine = coraza.RULE_ENGINE_OFF
		} else if a.allow == 2 {
			//tx.SkipToPhase = tx.LastPhase +1
		} else if a.allow == 3 && tx.LastPhase < 3 {
			//tx.SkipToPhase = 3
		}
	*/
}

func (a *allowFn) Type() rules.ActionType {
	return rules.ActionTypeDisruptive
}

func allow() rules.Action {
	return &allowFn{}
}

var (
	_ rules.Action      = (*allowFn)(nil)
	_ ruleActionWrapper = allow
)
