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

package seclang

import (
	"strings"
	"testing"

	"github.com/jptosso/coraza-waf/v2"
)

func TestDefaultActions(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	if err := p.AddDefaultActions("log, pass, phase: 1"); err != nil {
		t.Error("Error parsing default actions", err)
	}
	if err := p.AddDefaultActions("log, drop, phase:2"); err != nil {
		t.Error("Could not add default actions")
	}
	if len(p.GetDefaultActions()) != 2 {
		t.Error("Default actions were not created")
	}
	if err := p.FromString(`SecAction "phase:2, id:1"`); err != nil {
		t.Error("Could not create from string")
	}
}

func TestMergeActions(t *testing.T) {

}

func TestVariables(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	//single variable with key
	err := p.FromString(`SecRule REQUEST_HEADERS:test "" "id:1"`)
	if err != nil {
		t.Error(err)
	}
	err = p.FromString(`SecRule &REQUEST_COOKIES_NAMES:'/^(?:phpMyAdminphp|MyAdmin_https)$/' "id:2"`)
	if err != nil {
		t.Error(err)
	}
	err = p.FromString(`SecRule &REQUEST_COOKIES_NAMES:'/^(?:phpMyAdminphp|MyAdmin_https)$/'|ARGS:test "id:3"`)
	if err != nil {
		t.Error(err)
	}
	err = p.FromString(`SecRule &REQUEST_COOKIES_NAMES:'/.*/'|ARGS:/a|b/ "id:4"`)
	if err != nil {
		t.Error(err)
	}

	err = p.FromString(`SecRule &REQUEST_COOKIES_NAMES:'/.*/'|ARGS:/a|b/|XML:/*|ARGS|REQUEST_HEADERS "id:5"`)
	if err != nil {
		t.Error(err)
	}

	err = p.FromString(`SecRule XML:/*|XML://@* "" "id:6"`)
	if err != nil {
		t.Error(err)
	}
}

func TestVariableCases(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	err := p.FromString(`SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "" "id:7,pass"`)
	if err != nil {
		t.Error(err)
	}
}

func TestErrorLine(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	err := p.FromString("SecAction \"id:1\"\n#test\nSomefaulty")
	if err == nil {
		t.Error("that shouldn't happen o.o")
	}
	if !strings.Contains(err.Error(), "Line 3") {
		t.Error("failed to find error line, got " + err.Error())
	}
}
