// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

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
