// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3/rules"
)

type unconditionalMatch struct{}

func (*unconditionalMatch) Init(rules.OperatorOptions) error { return nil }

func (*unconditionalMatch) Evaluate(rules.TransactionState, string) bool { return true }
