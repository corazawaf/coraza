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
	"fmt"
	"strconv"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types"
)

type skipFn struct {
	data int
}

func (a *skipFn) Init(r *coraza.Rule, data string) error {
	i, err := strconv.Atoi(data)
	if err != nil {
		return fmt.Errorf("invalid value for skip")
	}
	if i < 1 {
		return fmt.Errorf("skip cannot be less than 1, got %d", i)
	}
	a.data = i
	return nil
}

func (a *skipFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	tx.Skip = a.data
}

func (a *skipFn) Type() types.RuleActionType {
	return types.ActionTypeFlow
}

func skip() coraza.RuleAction {
	return &skipFn{}
}

var (
	_ coraza.RuleAction = &skipFn{}
	_ ruleActionWrapper = skip
)
