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
	"github.com/jptosso/coraza-waf/v1/engine"
)

type Severity struct {
}

func (a *Severity) Init(r *engine.Rule, data string) string {
	l := []string{"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"}
	for _, val := range l {
		if val == data {
			//r.Severity = i
		}
	}
	r.Severity = data
	return ""
}

func (a *Severity) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	// Not evaluated
}

func (a *Severity) GetType() int {
	return engine.ACTION_TYPE_METADATA
}
