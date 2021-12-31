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
	"go.uber.org/zap"
)

type appendFn struct {
	data coraza.Macro
}

func (a *appendFn) Init(r *coraza.Rule, data string) error {
	macro, err := coraza.NewMacro(data)
	if err != nil {
		return err
	}
	a.data = *macro
	return nil
}

func (a *appendFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	if !tx.Waf.ContentInjection {
		tx.Waf.Logger.Debug("append rejected because of ContentInjection")
		return
	}
	data := a.data.Expand(tx)
	if _, err := tx.ResponseBodyBuffer.Write([]byte(data)); err != nil {
		tx.Waf.Logger.Error("append failed to write to response buffer", zap.Error(err))
	}
}

func (a *appendFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func append2() coraza.RuleAction {
	return &appendFn{}
}

var (
	_ coraza.RuleAction = &appendFn{}
	_ ruleActionWrapper = append2
)
