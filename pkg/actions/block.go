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
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Block struct{}

func (a *Block) Init(r *engine.Rule, b1 string) string {
	r.DisruptiveAction = engine.ACTION_DISRUPTIVE_BLOCK
	return ""
}

func (a *Block) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	if r.DefaultDisruptiveAction == "" {
		return
	}
	switch r.DefaultDisruptiveAction {
	case "drop":
		dr := &Drop{}
		dr.Evaluate(r, tx)
		break
	case "deny":
		dn := &Deny{}
		dn.Evaluate(r, tx)
		break
	case "allow":
		//not implemented
		break
	case "redirect":
		//not implemented
		break
	case "proxy":
		//not implemented
		break
	case "pause":
		//not implemented
		break
	default:
		ps := &Pass{}
		ps.Evaluate(r, tx)
		break
	}
}

func (a *Block) GetType() int {
	return engine.ACTION_TYPE_DISRUPTIVE
}
