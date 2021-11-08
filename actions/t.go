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
	"github.com/jptosso/coraza-waf/plugins"
	"github.com/jptosso/coraza-waf/transformations"
)

type T struct{}

func (a *T) Init(r *engine.Rule, input string) error {
	// TODO there is a chance that it won't work, it requires tests
	if input == "none" {
		//remove elements
		r.Transformations = r.Transformations[:0]
		return nil
	}
	transforms := transformations.TransformationsMap()
	tt := transforms[input]
	if tt == nil {
		//now we test from the plugins:
		if result, ok := plugins.CustomTransformations.Load(input); ok {
			tt = result.(transformations.Transformation)
		}
	}
	if tt == nil {
		return fmt.Errorf("unsupported transformation %s", input)
	}
	r.Transformations = append(r.Transformations, tt)
	return nil
}

func (a *T) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	// Not evaluated
}

func (a *T) Type() int {
	return engine.ACTION_TYPE_NONDISRUPTIVE
}
