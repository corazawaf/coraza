// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type idFn struct {
}

func (a *idFn) Init(r rules.RuleMetadata, data string) error {
	if data == "" {
		return fmt.Errorf("id action requires a parameter")
	}
	i, err := strconv.Atoi(data)
	if err != nil {
		return fmt.Errorf("invalid rule id %s", data)
	}
	// TODO(anuraaga): Confirm this is internal implementation detail
	rInt := r.(*corazawaf.Rule)
	rInt.ID_ = int(i)
	if rInt.ID_ < 0 {
		return fmt.Errorf("rule id (%d) cannot be negative", rInt.ID_)
	}
	if rInt.ID_ == 0 {
		return fmt.Errorf("rule id (%d) cannot be zero", rInt.ID_)
	}
	return nil
}

func (a *idFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	// Not evaluated
}

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
