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
	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types"
)

type blockFn struct{}

func (a *blockFn) Init(r *coraza.Rule, b1 string) error {
	return nil
}

func (a *blockFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// This should never run
}

func (a *blockFn) Type() types.RuleActionType {
	return types.ActionTypeDisruptive
}

func block() coraza.RuleAction {
	return &blockFn{}
}

var (
	_ coraza.RuleAction = &blockFn{}
	_ ruleActionWrapper = block
)
