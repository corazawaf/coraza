// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type idFn struct{}

func (a *idFn) Init(r rules.RuleMetadata, data string) error {
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

func (a *idFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {}

func (a *idFn) Type() rules.ActionType {
	return rules.ActionTypeMetadata
}

func id() rules.Action {
	return &idFn{}
}

var (
	_ rules.Action      = &idFn{}
	_ ruleActionWrapper = id
)
