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
	"testing"

	"github.com/jptosso/coraza-waf/v2"
)

func TestPmfm(t *testing.T) {
	data := "abc\r\ndef\r\nghi"
	p := &pmFromFile{}
	if err := p.Init(data); err != nil {
		t.Error(err)
	}
	waf := coraza.NewWaf()
	tx := waf.NewTransaction()
	if !p.Evaluate(tx, "def") {
		t.Error("failed to match pmFromFile")
	}
}
