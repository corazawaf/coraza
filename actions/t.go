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

	"github.com/jptosso/coraza-waf/v2"
	transformations "github.com/jptosso/coraza-waf/v2/transformations"
	"github.com/jptosso/coraza-waf/v2/types"
)

type tFn struct{}

func (a *tFn) Init(r *coraza.Rule, input string) error {
	// TODO there is a chance that it won't work, it requires tests
	// none is a special hardcoded transformation, it must remove previous transformations
	if input == "none" {
		//remove elements
		r.ClearTransformations()
		return nil
	}
	transforms := transformations.TransformationsMap()
	tt := transforms[input]
	if tt == nil {
		return fmt.Errorf("unsupported transformation %s", input)
	}
	return r.AddTransformation(input, tt)
}

func (a *tFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *tFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func t() coraza.RuleAction {
	return &tFn{}
}

var (
	_ coraza.RuleAction = &tFn{}
	_ RuleActionWrapper = t
)
