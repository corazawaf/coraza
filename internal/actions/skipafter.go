// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
)

type skipafterFn struct {
	data string
}

func (a *skipafterFn) Init(_ plugintypes.RuleMetadata, data string) error {
	data = utils.MaybeRemoveQuotes(data)
	if len(data) == 0 {
		return ErrMissingArguments
	}
	a.data = data
	return nil
}

func (a *skipafterFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	tx.DebugLogger().Debug().
		Str("value", a.data).
		Msg("Starting secmarker")
	tx.(*corazawaf.Transaction).SkipAfter = a.data
}

func (a *skipafterFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeFlow
}

func skipafter() plugintypes.Action {
	return &skipafterFn{}
}

var (
	_ plugintypes.Action = &skipafterFn{}
	_ ruleActionWrapper  = skipafter
)
