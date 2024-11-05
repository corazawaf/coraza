// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// Action Group: Flow
//
// Description:
// Skips one or more rules (or chained rules) on successful match.
// It only within the current processing phase and not necessarily in the order in which the rules appear in the configuration file.
// If you place a phase 2 rule after a phase 1 rule that uses skip, it will not skip over the phase 2 rule,
// it will skip over the next phase 1 rule that follows it in the phase.
//
// Example:
// ```
// # Require Accept header, but not from access from the localhost
// SecRule REMOTE_ADDR "^127\.0\.0\.1$" "phase:1,skip:1,id:141"
//
// # This rule will be skipped over when REMOTE_ADDR is 127.0.0.1
// SecRule &REQUEST_HEADERS:Accept "@eq 0" "phase:1,id:142,deny,msg:'Request Missing an Accept Header'"
// ```
type skipFn struct {
	data int
}

func (a *skipFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

	i, err := strconv.Atoi(data)
	if err != nil {
		return err
	}
	if i < 1 {
		return fmt.Errorf("invalid argument, %d must be greater than 1", i)
	}
	a.data = i
	return nil
}

func (a *skipFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	tx.(*corazawaf.Transaction).Skip = a.data
}

func (a *skipFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeFlow
}

func skip() plugintypes.Action {
	return &skipFn{}
}

var (
	_ plugintypes.Action = &skipFn{}
	_ ruleActionWrapper  = skip
)
