// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.detectXSS

package operators

import (
	"github.com/corazawaf/libinjection-go"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type detectXSS struct{}

var _ plugintypes.Operator = (*detectXSS)(nil)

func newDetectXSS(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &detectXSS{}, nil
}

func (o *detectXSS) Evaluate(_ plugintypes.TransactionState, value string) bool {
	return libinjection.IsXSS(value)
}

func init() {
	Register("detectXSS", newDetectXSS)
}
