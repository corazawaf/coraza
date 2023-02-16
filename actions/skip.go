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
		return err
	}
	if i < 1 {
		return fmt.Errorf("invalid argument, %d must be greater than 1", i)
	}
	a.data = i
	return nil
}

func (a *skipFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
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
