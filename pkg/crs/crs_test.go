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

package crs

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
	"testing"
)

func TestCrs(t *testing.T) {
	waf := engine.NewWaf()
	c, err := NewCrs(nil)
	if err == nil {
		t.Error("Should fail with invalid waf")
	}

	c, err = NewCrs(waf)
	if err != nil {
		t.Error("Should not fail with valid waf")
		return
	}
	c.TemplateDir = "../../docs/crs/rules/"
	err = c.Build()
	if err != nil {
		t.Error("Failed to build rules", err)
	}
	l := len(waf.Rules.GetRules())

	if l == 0 {
		t.Error("No rules found")
	}

	if l < 500 {
		t.Error("Not enough CRS rules, found ", l)
	}
}
