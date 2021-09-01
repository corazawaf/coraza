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
	"github.com/jptosso/coraza-waf"
	"github.com/jptosso/coraza-waf/utils"
)

type Phase struct{}

func (a *Phase) Init(r *coraza.Rule, data string) error {
	p, err := utils.PhaseToInt(data)
	if err != nil {
		return err
	}
	r.Phase = coraza.Phase(p)
	return nil
}

func (a *Phase) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *Phase) Type() int {
	return coraza.ACTION_TYPE_METADATA
}
