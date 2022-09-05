// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type unconditionalMatch struct{}

func (o *unconditionalMatch) Init(options corazawaf.RuleOperatorOptions) error { return nil }

func (o *unconditionalMatch) Evaluate(tx *corazawaf.Transaction, value string) bool { return true }
