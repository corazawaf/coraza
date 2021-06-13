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
	"github.com/jptosso/coraza-waf/pkg/engine"
	"testing"
)

func TestDefaultActions(t *testing.T) {
	waf := engine.NewWaf()
	p, _ := NewParser(waf)
	err := p.AddDefaultActions("log, pass, phase: 1")
	if err != nil {
		t.Error("Error parsing default actions", err)
	}
	p.AddDefaultActions("log, drop, phase:2")
	if len(p.GetDefaultActions()) != 2 {
		t.Error("Default actions were not created")
	}
}

func TestMergeActions(t *testing.T) {

}
