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
	utils "github.com/jptosso/coraza-waf/v2/utils"
)

type msgFn struct {
}

func (a *msgFn) Init(r *coraza.Rule, data string) error {
	r.Msg = utils.RemoveQuotes(data)
	return nil
}

func (a *msgFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *msgFn) Type() coraza.RuleActionType {
	return coraza.ActionTypeMetadata
}

func msg() coraza.RuleAction {
	return &msgFn{}
}

var (
	_ coraza.RuleAction = &msgFn{}
	_ RuleActionWrapper = msg
)
