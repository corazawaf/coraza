// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/transformations"
)

// Action Group: Non-disruptive
//
// Description:
// `t` is used to specify the transformation pipeline to use to transform the value of each variable used in the rule before matching.
// Any transformation functions that you specify in a `SecRule` will be added to the previous ones specified in `SecDefaultAction`.
// It is recommended that you always use `t:none` in your rules, which prevents them depending on the default configuration.
//
// Example:
// ```
// SecRule ARGS "(asfunction|javascript|vbscript|data|mocha|livescript):" "id:146,t:none,t:htmlEntityDecode,t:lowercase,t:removeNulls,t:removeWhitespace"
// ```
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
