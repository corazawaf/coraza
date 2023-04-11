// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type statusFn struct{}

func (a *statusFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

	// TODO(jcchavezs): Shall we validate valid status e.g. >200 && <600?
	status, err := strconv.Atoi(data)
	if err != nil {
		return fmt.Errorf("invalid argument: %s", err.Error())
	}
	r.(*corazawaf.Rule).DisruptiveStatus = status
	return nil
}

func (a *statusFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *statusFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeData
}

func status() plugintypes.Action {
	return &statusFn{}
}

var (
	_ plugintypes.Action = &statusFn{}
	_ ruleActionWrapper  = status
)
