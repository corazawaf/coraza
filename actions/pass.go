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

type passFn struct {
}

func (a *passFn) Init(r *coraza.Rule, data string) error {
	return nil
}

func (a *passFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *passFn) Type() types.RuleActionType {
	return types.ActionTypeDisruptive
}

func pass() coraza.RuleAction {
	return &passFn{}
}

var (
	_ coraza.RuleAction = &passFn{}
	_ ruleActionWrapper = pass
)
