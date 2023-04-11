// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/transformations"
)

type tFn struct{}

func (a *tFn) Init(r plugintypes.RuleMetadata, data string) error {
	// TODO there is a chance that it won't work, it requires tests
	// none is a special hardcoded transformation, it must remove previous transformations
	if data == "none" {
		// remove elements
		r.(*corazawaf.Rule).ClearTransformations()
		return nil
	}

	tt, err := transformations.GetTransformation(data)
	if err != nil {
		return err
	}
	return r.(*corazawaf.Rule).AddTransformation(data, tt)
}

func (a *tFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *tFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func t() plugintypes.Action {
	return &tFn{}
}

var (
	_ plugintypes.Action = &tFn{}
	_ ruleActionWrapper  = t
)
