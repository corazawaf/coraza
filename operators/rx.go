// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.rx

package operators

import (
	"fmt"
	"regexp"

	"github.com/corazawaf/coraza/v3/rules"
)

type rx struct {
	re *regexp.Regexp
}

var _ rules.Operator = (*rx)(nil)

func newRX(options rules.OperatorOptions) (rules.Operator, error) {
	// (?sm) enables multiline mode which makes 942522-7 work, see
	// - https://stackoverflow.com/a/27680233
	// - https://groups.google.com/g/golang-nuts/c/jiVdamGFU9E
	data := fmt.Sprintf("(?sm)%s", options.Arguments)
	re, err := regexp.Compile(data)
	if err != nil {
		return nil, err
	}
	return &rx{re: re}, nil
}

func (o *rx) Evaluate(tx rules.TransactionState, value string) bool {

	if tx.Capturing() {
		match := o.re.FindStringSubmatch(value)
		if len(match) == 0 {
			return false
		}
		for i, c := range match {
			if i == 9 {
				return true
			}
			tx.CaptureField(i, c)
		}
		return true
	} else {
		return o.re.MatchString(value)
	}
}

func init() {
	Register("rx", newRX)
}
