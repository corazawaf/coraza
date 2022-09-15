// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"bytes"
	"regexp"

	"github.com/corazawaf/coraza/v3/rules"
)

type rx struct {
	re *regexp.Regexp
}

var _ rules.Operator = (*rx)(nil)

func (o *rx) Init(options rules.OperatorOptions) error {
	data := options.Arguments

	re, err := regexp.Compile(data)
	o.re = re
	return err
}

func (o *rx) Evaluate(tx rules.TransactionState, value string) bool {
	match := o.re.FindAllSubmatch(o.convert(value), 1)
	lcount := len(match)
	if lcount == 0 {
		return false
	}

	if tx.Capturing() {
		for i, c := range match[0] {
			if i == 9 {
				return true
			}
			tx.CaptureField(i, string(c))
		}
	}

	return true
}

func (o *rx) convert(src string) []byte {
	var buf bytes.Buffer
	for i := range src {
		buf.WriteRune(rune(src[i]))
	}
	return buf.Bytes()
}
