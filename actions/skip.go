// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type skipFn struct {
	data int
}

func (a *skipFn) Init(_ rules.RuleMetadata, data string) error {
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

func (a *skipFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	// TODO(anuraaga): Confirm this is internal implementation detail
	tx.(*corazawaf.Transaction).Skip = a.data
}

func (a *skipFn) Type() rules.ActionType {
	return rules.ActionTypeFlow
}

func skip() rules.Action {
	return &skipFn{}
}

var (
	_ rules.Action      = &skipFn{}
	_ ruleActionWrapper = skip
)
