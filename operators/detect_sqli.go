// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/libinjection-go"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type detectSQLi struct{}

func (o *detectSQLi) Init(options corazawaf.RuleOperatorOptions) error { return nil }

func (o *detectSQLi) Evaluate(tx *corazawaf.Transaction, value string) bool {
	res, fingerprint := libinjection.IsSQLi(value)
	if !res {
		return false
	}
	if tx.Capture {
		tx.CaptureField(0, string(fingerprint))
	}
	return true
}
