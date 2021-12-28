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
	"fmt"
	"strconv"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types"
)

type maturityFn struct {
}

func (a *maturityFn) Init(r *coraza.Rule, data string) error {
	m, err := strconv.Atoi(data)
	if err != nil {
		return err
	}
	if m < 1 || m > 9 {
		return fmt.Errorf("maturity must be between 1 and 9, not %d", m)
	}
	r.Maturity = m
	return nil
}

func (a *maturityFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *maturityFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func maturity() coraza.RuleAction {
	return &maturityFn{}
}

var (
	_ coraza.RuleAction = &maturityFn{}
	_ ruleActionWrapper = maturity
)
