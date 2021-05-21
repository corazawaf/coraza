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

package operators

import (
	_ "fmt"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"testing"
)

func TestValidateNid(t *testing.T) {
	vicl := &ValidateNid{}
	vicl.Init("cl .*")

	clok := []string{"11.111.111-1", "111111111"}
	clfail := []string{"11.111.111-2", "111111118"}
	waf := &engine.Waf{}
	waf.Init()
	tx := waf.NewTransaction()
	for _, ok := range clok {
		if !vicl.Evaluate(tx, ok) {
			t.Errorf("Invalid NID " + ok)
		}
	}
	for _, fail := range clfail {
		if vicl.Evaluate(tx, fail) {
			t.Errorf("Invalid NID")
		}
	}
}
