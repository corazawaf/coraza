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

package actions

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Deny struct{}

func (a *Deny) Init(r *engine.Rule, data string) string {
	r.DisruptiveAction = engine.ACTION_DISRUPTIVE_DENY
	return ""
}

func (a *Deny) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	tx.Status = 403
	if r.ParentId == 0 {
		tx.DisruptiveRuleId = r.Id
	} else {
		tx.DisruptiveRuleId = r.ParentId
	}
	tx.Disrupted = true
}

func (a *Deny) GetType() int {
	return engine.ACTION_TYPE_DISRUPTIVE
}
