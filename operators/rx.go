// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package operators

import (
	"bytes"
	"regexp"

	"github.com/corazawaf/coraza/v3"
)

type rx struct {
	re *regexp.Regexp
}

func (o *rx) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments

	re, err := regexp.Compile(data)
	o.re = re
	return err
}

func (o *rx) Evaluate(tx *coraza.Transaction, value string) bool {
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
