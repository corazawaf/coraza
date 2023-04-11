// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type skipFn struct {
	data int
}

func (a *skipFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

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

func (a *skipFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	tx.(*corazawaf.Transaction).Skip = a.data
}

func (a *skipFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeFlow
}

func skip() plugintypes.Action {
	return &skipFn{}
}

var (
	_ plugintypes.Action = &skipFn{}
	_ ruleActionWrapper  = skip
)
