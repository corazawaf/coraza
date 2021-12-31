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
	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types"
)

type severityFn struct {
}

func (a *severityFn) Init(r *coraza.Rule, data string) error {
	sev, err := types.ParseRuleSeverity(data)
	if err != nil {
		return err
	}
	r.Severity = sev
	return nil
}

func (a *severityFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *severityFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func severity() coraza.RuleAction {
	return &severityFn{}
}

var (
	_ coraza.RuleAction = &severityFn{}
	_ ruleActionWrapper = severity
)
