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

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types"
	"github.com/corazawaf/coraza/v2/types/variables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCtl(t *testing.T) {
	waf := coraza.NewWaf()
	tx := waf.NewTransaction()
	r := coraza.NewRule()
	ctlf := ctl()

	err := ctlf.Init(r, "requestBodyProcessor=XML")
	require.NoError(t, err, "failed to init requestBodyProcessor=XML")

	ctlf.Evaluate(r, tx)
	// Not implemented yet

	err = ctlf.Init(r, "ruleRemoveTargetById=981260;ARGS:user")
	require.NoError(t, err, "failed to init ruleRemoveTargetById=981260;ARGS:user")

	ctlf.Evaluate(r, tx)
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

	err = ctlf.Init(r, "auditEngine=Off")
	require.NoError(t, err, "failed to init ctl with auditEngine=Off")
	ctlf.Evaluate(r, tx)

	require.Equal(t, types.AuditEngineOff, tx.AuditEngine, "failed to disable audit log")

	err = ctlf.Init(r, "ruleEngine=Off")
	require.NoError(t, err, "failed to init ctl using ruleEngine=Off")

	ctlf.Evaluate(r, tx)

	require.Equalf(t, types.RuleEngineOff, tx.RuleEngine, "failed to disable rule engine, got %s", tx.RuleEngine.String())

	err = ctlf.Init(r, "requestBodyLimit=12345")
	require.NoError(t, err, "failed to init ctl with requestBodyLimit=12345")

	ctlf.Evaluate(r, tx)

	require.Equal(t, int64(12345), tx.RequestBodyLimit, "failed to set request body limit")

	bodyprocessors := []string{"XML", "JSON", "URLENCODED", "MULTIPART"}
	for _, bp := range bodyprocessors {
		t.Run(bp, func(t *testing.T) {
			err = ctlf.Init(r, "requestBodyProcessor="+bp)
			assert.NoError(t, err, "failed to init requestBodyProcessor")

			ctlf.Evaluate(r, tx)

			assert.Equal(t, bp, tx.GetCollection(variables.ReqbodyProcessor).GetFirstString(""), "failed to set RequestBodyProcessor")
		})
	}
}

func TestCtlParseRange(t *testing.T) {
	a := &ctlFn{}
	rules := []*coraza.Rule{
		{ID: 5},
		{ID: 15},
	}
	ints, err := a.rangeToInts(rules, "1-2")
	require.NoError(t, err, "failed to parse range")
	require.Empty(t, ints, "failed to parse range")

	ints, err = a.rangeToInts(rules, "4-5")
	require.NoError(t, err, "failed to parse range")
	require.Len(t, ints, 1, "failed to parse range")

	ints, err = a.rangeToInts(rules, "4-15")
	require.NoError(t, err, "failed to parse range")
	require.Len(t, ints, 2, "failed to parse range")

	ints, err = a.rangeToInts(rules, "5")
	require.NoError(t, err, "failed to parse range")
	require.Len(t, ints, 1, "failed to parse range")

	_, err = a.rangeToInts(rules, "test")
	require.Error(t, err, "failed to parse range")
}
