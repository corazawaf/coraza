// Copyright 2020 Juan Pablo Tosso
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

package operators

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
	"testing"
)

func TestOpEq(t *testing.T) {
	waf := &engine.Waf{}
	waf.Init()
	tx := waf.NewTransaction()
	op := &Eq{}
	op.Init("123")
	result := op.Evaluate(tx, "123")
	if !result {
		t.Errorf("Invalid Eq operator result")
	}
	result = op.Evaluate(tx, "aaa")
	if result {
		t.Errorf("Invalid Eq operator result")
	}

	// aaa should be 0
	op.Init("0")
	result = op.Evaluate(tx, "aaa")
	if !result {
		t.Errorf("Invalid Eq operator result")
	}
}
