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
	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types"
)

type auditlogFn struct{}

func (a *auditlogFn) Init(r *coraza.Rule, data string) error {
	r.Audit = true
	return nil
}

func (a *auditlogFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Nothing here
}

func (a *auditlogFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func auditlog() coraza.RuleAction {
	return &auditlogFn{}
}

var (
	_ coraza.RuleAction = (*auditlogFn)(nil)
	_ ruleActionWrapper = auditlog
)
