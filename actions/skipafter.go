// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/rules"
)

type skipafterFn struct {
	data string
}

func (a *skipafterFn) Init(_ rules.RuleMetadata, data string) error {
	data = utils.MaybeRemoveQuotes(data)
	if len(data) == 0 {
		return ErrMissingArguments
	}
	a.data = data
	return nil
}

func (a *skipafterFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	tx.(*corazawaf.Transaction).SkipAfter = a.data
}

func (a *skipafterFn) Type() rules.ActionType {
	return rules.ActionTypeFlow
}

func skipafter() rules.Action {
	return &skipafterFn{}
}

var (
	_ rules.Action      = &skipafterFn{}
	_ ruleActionWrapper = skipafter
)
