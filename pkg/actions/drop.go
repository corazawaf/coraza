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

type Drop struct{}

func (a *Drop) Init(r *engine.Rule, data string) string {
	r.DisruptiveAction = engine.ACTION_DISRUPTIVE_DROP
	return ""
}

func (a *Drop) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	tx.Status = 403
	tx.Disrupted = true
	tx.DisruptiveRuleId = r.Id
	//TODO maybe send a TCP RST using the ip address and port?
}

func (a *Drop) GetType() int {
	return engine.ACTION_TYPE_DISRUPTIVE
}
