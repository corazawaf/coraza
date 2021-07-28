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
	Data string
}

func (a *Append) Init(r *engine.Rule, data string) error {
	a.Data = data
	return nil
}

func (a *Append) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	// Not implemented
}

func (a *Append) GetType() int {
	return engine.ACTION_TYPE_METADATA
}
