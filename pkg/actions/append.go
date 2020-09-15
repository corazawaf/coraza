// Copyright 2020 Juan Pablo Tosso
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

package actions

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Append struct {
	Data string
}

func (a *Append) Init(r *engine.Rule, data string) string {
	a.Data = data
	return ""
}

func (a *Append) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	t := tx.GetCollection("tx")
	rb := t.GetSimple("response_body")
	if len(rb) > 0 {
		t.Set("response_body", []string{rb[0] + a.Data})
	}
}

func (a *Append) GetType() int {
	return engine.ACTION_TYPE_METADATA
}
