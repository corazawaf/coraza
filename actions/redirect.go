// Copyright 2022 The Corazawaf Authors
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
	"fmt"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type redirectFn struct {
	target string
}

func (a *redirectFn) Init(r *coraza.Rule, data string) error {
	if data == "" {
		return fmt.Errorf("redirect action requires a parameter")
	}

	a.target = data
	r.Disruptive = true
	return nil
}

func (a *redirectFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	rid := r.ID
	if rid == 0 {
		rid = r.ParentID
	}
	if tx.RuleEngine == types.RuleEngineOn {
		tx.Interruption = &types.Interruption{
			Status: r.DisruptiveStatus,
			RuleID: rid,
			Action: "redirect",
			Data:   a.target,
		}
	}
}

func (a *redirectFn) Type() types.RuleActionType {
	return types.ActionTypeDisruptive
}

func redirect() coraza.RuleAction {
	return &redirectFn{}
}

var (
	_ coraza.RuleAction = &redirectFn{}
	_ ruleActionWrapper = redirect
)
