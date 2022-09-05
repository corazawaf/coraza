// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"strconv"

	"github.com/corazawaf/coraza/v3/types"
)

type skipFn struct {
	data int
}

func (a *skipFn) Init(r *corazawaf.Rule, data string) error {
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

func (a *skipFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	tx.Skip = a.data
}

func (a *skipFn) Type() types.RuleActionType {
	return types.ActionTypeFlow
}

func skip() corazawaf.RuleAction {
	return &skipFn{}
}

var (
	_ corazawaf.RuleAction = &skipFn{}
	_ ruleActionWrapper    = skip
)
