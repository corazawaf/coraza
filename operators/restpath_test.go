// Copyright 2022 Juan Pablo Tosso
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
	"context"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestRestPath(t *testing.T) {
	waf := coraza.NewWaf()
	tx := waf.NewTransaction(context.Background())
	exp := "/some-random/url-{id}/{name}"
	path := "/some-random/url-123/juan"
	rp := restpath{}
	if err := rp.Init(coraza.RuleOperatorOptions{
		Arguments: exp,
	}); err != nil {
		t.Error(err)
	}
	if !rp.Evaluate(tx, path) {
		t.Errorf("Expected %s to match %s", exp, path)
	}
	if tx.Variables.ArgsPath.Get("id")[0] != "123" {
		t.Errorf("Expected 123, got %s", tx.Variables.ArgsPath.Get("id"))
	}
}
