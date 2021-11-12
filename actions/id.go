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

type idFn struct {
}

func (a *idFn) Init(r *coraza.Rule, data string) error {
	if data == "" {
		return fmt.Errorf("id action requires a parameter")
	}
	i, err := strconv.Atoi(data)
	if err != nil {
		return fmt.Errorf("invalid rule id %s", data)
	}
	r.Id = int(i)
	if r.Id < 0 {
		return fmt.Errorf("rule id (%d) cannot be negative", r.Id)
	}
	if r.Id == 0 {
		return fmt.Errorf("rule id (%d) cannot be zero", r.Id)
	}
	return nil
}

func (a *idFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *idFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func id() coraza.RuleAction {
	return &idFn{}
}

var (
	_ coraza.RuleAction = &idFn{}
	_ ruleActionWrapper = id
)
