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
	"github.com/jptosso/coraza-waf/v1/engine"
)

type Deny struct{}

func (a *Deny) Init(r *engine.Rule, data string) string {
	r.DisruptiveAction = engine.ACTION_DISRUPTIVE_DENY
	return ""
}

func (a *Deny) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	rid := r.Id
	if rid == 0 {
		rid = r.ParentId
	}
	tx.Interruption = &engine.Interruption{
		Status: 403,
		RuleId: rid,
		Action: "deny",
	}
}

func (a *Deny) GetType() int {
	return engine.ACTION_TYPE_DISRUPTIVE
}
