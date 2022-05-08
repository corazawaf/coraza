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

	"github.com/corazawaf/coraza/v2"
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

	data = "\r\nasd\r\n# 123\r\n\r\n\r\n"
	if err := p.Init(data); err != nil {
		t.Error(err)
	}
	tx = waf.NewTransaction()
	if !p.Evaluate(tx, "asd") {
		t.Error("failed to match pmFromFile")
	}
	if p.Evaluate(tx, "123") {
		t.Error("failed to match pmFromFile")
	}

	data = "\nSecRuleRemoveById 123456\r\n\n# SecRuleRemoveById 234567\r\n\r\n\n\r\n" // Mix LF & CRLF
	if err := p.Init(data); err != nil {
		t.Error(err)
	}
	tx = waf.NewTransaction()
	if !p.Evaluate(tx, "SecRuleRemoveById 123456") {
		t.Error("failed to match pmFromFile")
	}

}
