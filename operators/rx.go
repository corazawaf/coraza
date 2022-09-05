// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"bytes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"regexp"
)

type rx struct {
	re *regexp.Regexp
}

func (o *rx) Init(options corazawaf.RuleOperatorOptions) error {
	data := options.Arguments

	re, err := regexp.Compile(data)
	o.re = re
	return err
}

func (o *rx) Evaluate(tx *corazawaf.Transaction, value string) bool {
	match := o.re.FindAllSubmatch(o.convert(value), -1)
	lcount := len(match)
	if !tx.Capture && lcount > 0 {
		return true
	}

	if lcount > 0 && tx.Capture {
		for i, c := range match[0] {
			if i == 9 {
				return true
			}
			tx.CaptureField(i, string(c))
		}
	}
	return lcount > 0
}

func (o *rx) convert(src string) []byte {
	var buf bytes.Buffer
	for i := range src {
		buf.WriteRune(rune(src[i]))
	}
	return buf.Bytes()
}
