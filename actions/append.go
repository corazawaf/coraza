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

import engine "github.com/jptosso/coraza-waf"

type Append struct {
	data string
}

func (a *Append) Init(r *engine.Rule, data string) error {
	a.data = data
	return nil
}

func (a *Append) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	if !tx.Waf.ContentInjection {
		tx.Waf.Logger.Debug("append rejected because of ContentInjection")
		return
	}
	data := tx.MacroExpansion(a.data)
	if _, err := tx.ResponseBodyBuffer.Write([]byte(data)); err != nil {
		tx.Waf.Logger.Debug("append failed to write to response buffer")
	}
}

func (a *Append) Type() int {
	return engine.ACTION_TYPE_NONDISRUPTIVE
}
