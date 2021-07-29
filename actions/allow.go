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
	"fmt"

	engine "github.com/jptosso/coraza-waf"
)

//0 nothing, 1 phase, 2 request
type Allow struct {
	allow int
}

func (a *Allow) Init(r *engine.Rule, b1 string) error {
	// Does not require
	if b1 == "phase" {
		a.allow = 1
	} else if b1 == "request" {
		a.allow = 2
	} else if b1 == "" {
		a.allow = 0
	} else {
		fmt.Errorf("Invalid value for action allow")
	}
	return nil
}

func (a *Allow) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	//Huge TODO here
}

func (a *Allow) GetType() int {
	return engine.ACTION_TYPE_DISRUPTIVE
}
