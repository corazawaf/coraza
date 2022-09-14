// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3"
)

type unconditionalMatch struct{}

func (*unconditionalMatch) Init(coraza.RuleOperatorOptions) error { return nil }

func (*unconditionalMatch) Evaluate(*coraza.Transaction, string) bool { return true }
