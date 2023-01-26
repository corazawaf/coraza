// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasilibs

import (
	"github.com/wasilibs/go-re2"

	"github.com/corazawaf/coraza/v3/operators"
	"github.com/corazawaf/coraza/v3/rules"
)

type rx struct {
	re *re2.Regexp
}

var _ rules.Operator = (*rx)(nil)

func newRX(options rules.OperatorOptions) (rules.Operator, error) {
	o := &rx{}
	data := options.Arguments

	re, err := re2.Compile(data)
	if err != nil {
		return nil, err
	}

	o.re = re
	return o, err
}

func (o *rx) Evaluate(tx rules.TransactionState, value string) bool {
	match := o.re.FindStringSubmatch(value)
	if len(match) == 0 {
		return false
	}

	if tx.Capturing() {
		for i, c := range match {
			if i == 9 {
				return true
			}
			tx.CaptureField(i, c)
		}
	}

	return true
}

// RegisterRX registers the rx operator using a WASI implementation instead of Go.
func RegisterRX() {
	operators.Register("rx", newRX)
}
