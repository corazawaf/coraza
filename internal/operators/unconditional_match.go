// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.unconditionalMatch

package operators

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type unconditionalMatch struct{}

func newUnconditionalMatch(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &unconditionalMatch{}, nil
}

func (*unconditionalMatch) Evaluate(plugintypes.TransactionState, string) bool { return true }

func init() {
	Register("unconditionalMatch", newUnconditionalMatch)
}
