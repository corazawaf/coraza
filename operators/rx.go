// Copyright 2021 Juan Pablo Tosso
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

	engine "github.com/jptosso/coraza-waf/v2"
)

type rx struct {
	re *regexp.Regexp
}

func (o *rx) Init(data string) error {
	re, err := regexp.Compile(data)
	o.re = re
	return err
}

func (o *rx) Evaluate(tx *engine.Transaction, value string) bool {
	// iterate over re if it matches value

	match := o.re.FindAllString(value, -1)
	if len(match) > 0 {
		tx.CaptureField(0, value)
	}
	for i, m := range match {
		if i == 9 {
			return true
		}
		//I actually think everything should be capturable, there is no need for the capture action...
		//if tx.IsCapturable() {
		tx.CaptureField(i+1, m)
		//}
	}
	return len(match) > 0
}
