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
	"github.com/jptosso/coraza-waf/pkg/engine"
	regex "github.com/jptosso/coraza-waf/pkg/utils/regex"
)

type Rx struct {
	re regex.Regexp
}

func (o *Rx) Init(data string) {
	o.re = regex.MustCompile(data, 0)
}

func (o *Rx) Evaluate(tx *engine.Transaction, value string) bool {
	m := o.re.MatcherString(value, 0)
	for i := 0; i < m.Groups()+1; i++ {
		if i == 10 {
			return true
		}
		//I actually think everything should be capturable, there is no need for the capture action...
		//if tx.IsCapturable() {
		tx.CaptureField(i, m.GroupString(i))
		//}
	}
	return m.Matches()
}
