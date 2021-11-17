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

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types"
)

// 0 nothing, 1 phase, 2 request
type allowFn struct {
	allow int
}

func (a *allowFn) Init(r *coraza.Rule, b1 string) error {
	switch b1 {
	case "phase":
		a.allow = 2 // skip current phase
	case "request":
		a.allow = 3 // skip phases until RESPONSE_HEADERS
	case "":
		a.allow = 1 // skip all phases
	default:
		return fmt.Errorf("invalid argument %s for allow", b1)
	}
	return nil
}

func (a *allowFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// TODO implement this:
	/*
		if a.allow == 1 {
			tx.RuleEngine = coraza.RULE_ENGINE_OFF
		} else if a.allow == 2 {
			//tx.SkipToPhase = tx.LastPhase +1
		} else if a.allow == 3 && tx.LastPhase < 3 {
			//tx.SkipToPhase = 3
		}
	*/
}

func (a *allowFn) Type() types.RuleActionType {
	return types.ActionTypeDisruptive
}

func allow() coraza.RuleAction {
	return &allowFn{}
}

var (
	_ coraza.RuleAction = (*allowFn)(nil)
	_ ruleActionWrapper = allow
)
