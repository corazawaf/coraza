// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v4/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v4/internal/corazawaf"
)

// Action Group: Metadata
//
// Description:
// > This action is mandatory for all `SecRule` and `SecAction`, and it must be numeric.
// Assigns a unique ID to the rule or chain in which it appears.
//
// Example:
// ```
// SecRule &REQUEST_HEADERS:Host "@eq 0" "log,id:60008,severity:2,msg:'Request Missing a Host Header'"
// ```
type idFn struct{}

func (a *idFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}
	i, err := strconv.Atoi(data)
	if err != nil {
		return err
	}

	if i <= 0 {
		return fmt.Errorf("invalid id argument, %d must be positive", i)
	}

	cr := r.(*corazawaf.Rule)
	cr.ID_ = int(i)
	return nil
}

func (a *idFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *idFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeMetadata
}

func id() plugintypes.Action {
	return &idFn{}
}

var (
	_ plugintypes.Action = &idFn{}
	_ ruleActionWrapper  = id
)
