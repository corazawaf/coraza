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
	"testing"

	"github.com/jptosso/coraza-waf/v2"
)

func TestCtl(t *testing.T) {
	waf := coraza.NewWaf()
	tx := waf.NewTransaction()
	r := coraza.NewRule()
	ctl := Ctl{}

	if err := ctl.Init(r, "requestBodyProcessor=XML"); err != nil {
		t.Error("Failed to init requestBodyProcessor=XML")
	}
	ctl.Evaluate(r, tx)
	// Not implemented yet

	if err := ctl.Init(r, "ruleRemoveTargetById=981260;ARGS:user"); err != nil {
		t.Error("failed to init ruleRemoveTargetById=981260;ARGS:user")
	}
	ctl.Evaluate(r, tx)
	/*
		TODO
		if tx.ruleRemoveTargetById[981260] == nil {
			t.Error("Failed to create ruleRemoveTargetById")
		} else {
			if tx.ruleRemoveTargetById[981260][0].Collection != coraza.VARIABLE_ARGS {
				t.Error("Failed to create ruleRemoveTargetById, invalid Collection")
			}
			if tx.ruleRemoveTargetById[981260][0].Key != "user" {
				t.Error("Failed to create ruleRemoveTargetById, invalid Key")
			}
		}
	*/

	if err := ctl.Init(r, "auditEngine=Off"); err != nil {
		t.Error("failed to init ctl with auditEngine=Off")
	}
	ctl.Evaluate(r, tx)

	if tx.AuditEngine != coraza.AUDIT_LOG_DISABLED {
		t.Error("Failed to disable audit log")
	}

	if err := ctl.Init(r, "ruleEngine=Off"); err != nil {
		t.Error("failed to init ctl using ruleEngine=Off")
	}
	ctl.Evaluate(r, tx)

	if tx.RuleEngine != coraza.RULE_ENGINE_OFF {
		t.Error("Failed to disable rule engine")
	}

	if err := ctl.Init(r, "requestBodyLimit=12345"); err != nil {
		t.Error("failed to init ctl with requestBodyLimit=12345")
	}
	ctl.Evaluate(r, tx)

	if tx.RequestBodyLimit != 12345 {
		t.Error("Failed to set request body limit")
	}

	bodyprocessors := []string{"XML", "JSON", "URLENCODED", "MULTIPART"}
	for _, bp := range bodyprocessors {
		if err := ctl.Init(r, "requestBodyProcessor="+bp); err != nil {
			t.Errorf("failed to init requestBodyProcessor %s", bp)
		}
		ctl.Evaluate(r, tx)
		if tx.GetCollection(coraza.VARIABLE_REQBODY_PROCESSOR).GetFirstString("") != bp {
			t.Error("failed to set RequestBodyProcessor " + bp)
		}
	}
}
