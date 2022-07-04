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

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type dropFn struct{}

func (a *dropFn) Init(r *coraza.Rule, data string) error {
	r.Disruptive = true
	return nil
}

func (a *dropFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	rid := r.ID
	if rid == 0 {
		rid = r.ParentID
	}
	if tx.RuleEngine == types.RuleEngineOn {
		tx.Interruption = &types.Interruption{
			Status: r.DisruptiveStatus,
			RuleID: rid,
			Action: "drop",
		}
	}
}

func (a *dropFn) Type() types.RuleActionType {
	return types.ActionTypeDisruptive
}

func drop() coraza.RuleAction {
	return &dropFn{}
}

var (
	_ coraza.RuleAction = &dropFn{}
	_ ruleActionWrapper = drop
)
