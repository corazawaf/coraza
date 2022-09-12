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

	"github.com/corazawaf/coraza/v3/rules"
	"github.com/corazawaf/coraza/v3/types"
)

type redirectFn struct {
	target string
}

func (a *redirectFn) Init(r rules.Rule, data string) error {
	if data == "" {
		return fmt.Errorf("redirect action requires a parameter")
	}

	a.target = data
	return nil
}

func (a *redirectFn) Evaluate(r rules.Rule, tx rules.TransactionState) {
	rid := r.IDString()
	if rid == 0 {
		rid = r.ParentIDString()
	}
	tx.Interrupt(&types.Interruption{
		Status: r.Status(),
		RuleID: rid,
		Action: "redirect",
		Data:   a.target,
	})
}

func (a *redirectFn) Type() rules.ActionType {
	return rules.ActionTypeDisruptive
}

func redirect() rules.Action {
	return &redirectFn{}
}

var (
	_ rules.Action      = &redirectFn{}
	_ ruleActionWrapper = redirect
)
