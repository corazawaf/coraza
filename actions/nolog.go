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

type nologFn struct {
}

func (a *nologFn) Init(r *coraza.Rule, data string) error {
	r.Log = false
	return nil
}

func (a *nologFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
}

func (a *nologFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func nolog() coraza.RuleAction {
	return &nologFn{}
}

var (
	_ coraza.RuleAction = &nologFn{}
	_ ruleActionWrapper = nolog
)
