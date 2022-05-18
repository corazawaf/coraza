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
	"strings"

	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types"
)

type skipafterFn struct {
	data string
}

func (a *skipafterFn) Init(r *coraza.Rule, data string) error {
	a.data = strings.Trim(data, `"`)
	return nil
}

func (a *skipafterFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	tx.Waf.Logger.WithFields(coraza.Fields{
		"txid":    tx.ID,
		"event":   "INIT_SECMARK",
		"secmark": a.data,
	}).Debug("Starting secmarker")
	tx.SkipAfter = a.data
}

func (a *skipafterFn) Type() types.RuleActionType {
	return types.ActionTypeFlow
}

func skipafter() coraza.RuleAction {
	return &skipafterFn{}
}

var (
	_ coraza.RuleAction = &skipafterFn{}
	_ ruleActionWrapper = skipafter
)
