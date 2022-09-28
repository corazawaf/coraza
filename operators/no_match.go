// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3/rules"
)

type noMatch struct{}

var _ rules.Operator = (*noMatch)(nil)

func (*noMatch) Init(options rules.OperatorOptions) error { return nil }

func (*noMatch) Evaluate(tx rules.TransactionState, value string) bool { return false }
