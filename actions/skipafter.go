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
	"strings"

	engine "github.com/jptosso/coraza-waf"
	"go.uber.org/zap"
)

type SkipAfter struct {
	data string
}

func (a *SkipAfter) Init(r *engine.Rule, data string) error {
	a.data = strings.Trim(data, `"`)
	return nil
}

func (a *SkipAfter) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	tx.Waf.Logger.Debug("Starting secmarker",
		zap.String("txid", tx.Id),
		zap.String("event", "INIT_SECMARK"),
		zap.String("secmark", a.data),
	)
	tx.SkipAfter = a.data
}

func (a *SkipAfter) Type() int {
	return engine.ACTION_TYPE_FLOW
}
