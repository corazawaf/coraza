// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type idFn struct {
}

func (a *idFn) Init(r *coraza.Rule, data string) error {
	if data == "" {
		return fmt.Errorf("id action requires a parameter")
	}
	i, err := strconv.Atoi(data)
	if err != nil {
		return fmt.Errorf("invalid rule id %s", data)
	}
	r.ID = int(i)
	if r.ID < 0 {
		return fmt.Errorf("rule id (%d) cannot be negative", r.ID)
	}
	if r.ID == 0 {
		return fmt.Errorf("rule id (%d) cannot be zero", r.ID)
	}
	return nil
}

func (a *idFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *idFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func id() coraza.RuleAction {
	return &idFn{}
}

var (
	_ coraza.RuleAction = &idFn{}
	_ ruleActionWrapper = id
)
