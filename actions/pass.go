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
	engine "github.com/jptosso/coraza-waf/v1"
)

type Pass struct {
}

func (a *Pass) Init(r *engine.Rule, data string) error {
	r.DisruptiveAction = engine.ACTION_DISRUPTIVE_PASS
	return nil
}

func (a *Pass) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	// Not evaluated
}

func (a *Pass) GetType() int {
	return engine.ACTION_TYPE_DISRUPTIVE
}
