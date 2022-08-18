// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type skipFn struct {
	data int
}

func (a *skipFn) Init(r *coraza.Rule, data string) error {
	i, err := strconv.Atoi(data)
	if err != nil {
		return fmt.Errorf("invalid value for skip")
	}
	if i < 1 {
		return fmt.Errorf("skip cannot be less than 1, got %d", i)
	}
	a.data = i
	return nil
}

func (a *skipFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	tx.Skip = a.data
}

func (a *skipFn) Type() types.RuleActionType {
	return types.ActionTypeFlow
}

func skip() coraza.RuleAction {
	return &skipFn{}
}

var (
	_ coraza.RuleAction = &skipFn{}
	_ ruleActionWrapper = skip
)
