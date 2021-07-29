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

	engine "github.com/jptosso/coraza-waf"
)

func TestCtl(t *testing.T) {
	waf := engine.NewWaf()
	tx := waf.NewTransaction()
	r := engine.NewRule()
	ctl := Ctl{}

	ctl.Init(r, "requestBodyProcessor=XML")
	ctl.Evaluate(r, tx)
	// Not implemented yet

	ctl.Init(r, "ruleRemoveTargetById=981260;ARGS:user")
	ctl.Evaluate(r, tx)

	if tx.RuleRemoveTargetById[981260] == nil {
		t.Error("Failed to create ruleRemoveTargetById")
	} else {
		if tx.RuleRemoveTargetById[981260][0].Collection != engine.VARIABLE_ARGS {
			t.Error("Failed to create ruleRemoveTargetById, invalid Collection")
		}
		if tx.RuleRemoveTargetById[981260][0].Key != "user" {
			t.Error("Failed to create ruleRemoveTargetById, invalid Key")
		}
	}

	ctl.Init(r, "auditEngine=Off")
	ctl.Evaluate(r, tx)

	if tx.AuditEngine != engine.AUDIT_LOG_DISABLED {
		t.Error("Failed to disable audit log")
	}

	ctl.Init(r, "ruleEngine=Off")
	ctl.Evaluate(r, tx)

	if tx.RuleEngine != engine.RULE_ENGINE_OFF {
		t.Error("Failed to disable rule engine")
	}

	ctl.Init(r, "requestBodyLimit=12345")
	ctl.Evaluate(r, tx)

	if tx.RequestBodyLimit != 12345 {
		t.Error("Failed to set request body limit")
	}

	bodyprocessors := []string{"XML", "JSON", "URLENCODED", "MULTIPART"}
	for _, bp := range bodyprocessors {
		ctl.Init(r, "requestBodyProcessor="+bp)
		ctl.Evaluate(r, tx)
		if tx.GetCollection(engine.VARIABLE_REQBODY_PROCESSOR).GetFirstString("") != bp {
			t.Error("failed to set RequestBodyProcessor " + bp)
		}
	}
}
