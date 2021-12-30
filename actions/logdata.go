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

type logdataFn struct {
}

func (a *logdataFn) Init(r *coraza.Rule, data string) error {
	macro, err := coraza.NewMacro(data)
	if err != nil {
		return err
	}
	r.LogData = *macro
	return nil
}

func (a *logdataFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	tx.Logdata = r.LogData.Expand(tx)
}

func (a *logdataFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func logdata() coraza.RuleAction {
	return &logdataFn{}
}

var (
	_ coraza.RuleAction = &logdataFn{}
	_ ruleActionWrapper = logdata
)
