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
	"regexp"

	"github.com/jptosso/coraza-waf/v2"
)

type rx struct {
	re *regexp.Regexp
}

func (o *rx) Init(data string) error {
	re, err := regexp.Compile(data)
	o.re = re
	return err
}

func (o *rx) Evaluate(tx *coraza.Transaction, value string) bool {
	match := o.re.FindAllString(value, -1)
	lcount := len(match)
	if !tx.Capture && lcount > 0 {
		return true
	}
	if lcount > 0 && tx.Capture {
		tx.CaptureField(0, value)
	}
	for i, m := range match {
		if i == 9 {
			return true
		}
		tx.CaptureField(i+1, m)
	}
	return lcount > 0
}
