// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"bytes"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/debuglogger"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestCtl(t *testing.T) {
	tests := []struct {
		input string
		check func(t *testing.T, logEntry string, tx *corazawaf.Transaction)
	}{
		{
			input: "ruleRemoveTargetById=123",
		},
		{
			input: "ruleRemoveTargetById=A",
			check: func(t *testing.T, logEntry string, tx *corazawaf.Transaction) {
				if wantToContain, have := "Invalid range", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("unexpected log entry: want to contain %q, have %q", wantToContain, logEntry)
				}
			},
		},
		{
			input: "ruleRemoveTargetByTag=tag1",
		},
		{
			input: "ruleRemoveTargetByMsg=somethingWentWrong",
		},
		{
			input: "auditEngine=Off",
			check: func(t *testing.T, logEntry string, tx *corazawaf.Transaction) {
				if tx.AuditEngine != types.AuditEngineOff {
					t.Error("Failed to set auditEngine")
				}
			},
		},
		{
			input: "auditEngine=In",
			check: func(t *testing.T, logEntry string, tx *corazawaf.Transaction) {
				if tx.AuditEngine != types.AuditEngineOn {
					t.Error("Failed to set auditEngine")
				}

				if wantToContain, have := "invalid audit engine status: In", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("unexpected log entry: want to contain %q, have %q", wantToContain, logEntry)
				}
			},
		},
		{
			input: "auditLogParts=A",
			check: func(t *testing.T, logEntry string, tx *corazawaf.Transaction) {
				if want, have := types.AuditLogPartAuditLogHeader, tx.AuditLogParts[0]; want != have {
					t.Errorf("Failed to set auditLogParts, want %s, have %s", string(want), string(have))
				}
			},
		},
		{
			input: "forceRequestBodyVariable=On",
			check: func(t *testing.T, logEntry string, tx *corazawaf.Transaction) {
				if want, have := true, tx.ForceRequestBodyVariable; want != have {
					t.Errorf("Failed to set forceRequestBodyVariable, want %t, have %t", want, have)
				}
			},
		},
		{
			input: "forceRequestBodyVariable=In",
			check: func(t *testing.T, logEntry string, tx *corazawaf.Transaction) {
				if tx.ForceRequestBodyVariable != false {
					t.Error("Failed to set forceRequestBodyVariable")
				}

				if wantToContain, have := "Unknown toggle", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("unexpected log entry: want to contain %q, have %q", wantToContain, logEntry)
				}
			},
		},
		{
			input: "requestBodyAccess=Off",
			check: func(t *testing.T, logEntry string, tx *corazawaf.Transaction) {
				if want, have := false, tx.RequestBodyAccess; want != have {
					t.Errorf("Failed to set requestBodyAccess, want %t, have %t", want, have)
				}
			},
		},
		{
			input: "requestBodyAccess=In",
			check: func(t *testing.T, logEntry string, tx *corazawaf.Transaction) {
				if tx.RequestBodyAccess != false {
					t.Error("Failed to set requestBodyAccess")
				}

				if wantToContain, have := "Unknown toggle", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("unexpected log entry: want to contain %q, have %q", wantToContain, logEntry)
				}
			},
		},
		{
			input: "requestBodyLimit=12345",
			check: func(t *testing.T, logEntry string, tx *corazawaf.Transaction) {
				if tx.RequestBodyLimit != 12345 {
					t.Error("Failed to set request body limit")
				}
			},
		},
		{
			input: "ruleEngine=Off",
			check: func(t *testing.T, logEntry string, tx *corazawaf.Transaction) {
				if tx.RuleEngine != types.RuleEngineOff {
					t.Errorf("Failed to disable rule engine, got %s", tx.RuleEngine.String())
				}
			},
		},
		{
			input: "ruleRemoveById=123",
		},
		{
			input: "ruleRemoveByMsg=somethingWentWrong",
		},
		{
			input: "ruleRemoveByTag=tag1",
		},
		{
			input: "requestBodyProcessor=XML",
			check: func(t *testing.T, logEntry string, tx *corazawaf.Transaction) {
				if want, have := tx.Variables().RequestBodyProcessor().Get(), "XML"; want != have {
					t.Errorf("failed to set requestBodyProcessor, want %s, have %s", want, have)
				}
			},
		},
		{
			input: "debugLogLevel=1",
		},
		{
			input: "debugLogLevel=A",
			check: func(t *testing.T, logEntry string, tx *corazawaf.Transaction) {
				if wantToContain, have := "Invalid log level", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("unexpected log entry: want to contain %q, have %q", wantToContain, logEntry)
				}
			},
		},
	}

	for _, test := range tests {
		testName, _, _ := strings.Cut(test.input, "=")
		t.Run(testName, func(t *testing.T) {
			logs := &bytes.Buffer{}
			waf := corazawaf.NewWAF()
			waf.Logger = debuglogger.Default().WithOutput(logs)
			r := corazawaf.NewRule()
			err := waf.Rules.Add(r)
			if err != nil {
				t.Fatalf("failed to add rule: %s", err.Error())
			}

			tx := waf.NewTransaction()
			a := ctl()
			if err := a.Init(r, test.input); err != nil {
				t.Fatalf("failed to init ctl: %s", err.Error())
			}

			a.Evaluate(r, tx)

			if test.check == nil {
				// TODO(jcchavezs): for some tests we can't do any assertion
				// without going too deep into the implementation details.
				// t.SkipNow() can't be used because tinygo doesn't support it.
				// https://github.com/tinygo-org/tinygo/blob/release/src/testing/testing.go#L246
				return
			} else {
				test.check(t, logs.String(), tx)
			}
		})
	}
}

func TestParseCtl(t *testing.T) {
	t.Run("invalid ctl", func(t *testing.T) {
		ctl, _, _, _, err := parseCtl("invalid")
		if err == nil {
			t.Errorf("expected error, got nil")
		}

		if ctl != ctlUnknown {
			t.Errorf("expected ctlUnknown, got %d", ctl)
		}
	})

	tCases := []struct {
		input            string
		expectAction     ctlFunctionType
		expectValue      string
		expectCollection variables.RuleVariable
		expectKey        string
	}{
		{"auditEngine=On", ctlAuditEngine, "On", variables.Unknown, ""},
		{"auditLogParts=A", ctlAuditLogParts, "A", variables.Unknown, ""},
		{"forceRequestBodyVariable=On", ctlForceRequestBodyVariable, "On", variables.Unknown, ""},
		{"requestBodyAccess=On", ctlRequestBodyAccess, "On", variables.Unknown, ""},
		{"requestBodyLimit=100", ctlRequestBodyLimit, "100", variables.Unknown, ""},
		{"requestBodyProcessor=JSON", ctlRequestBodyProcessor, "JSON", variables.Unknown, ""},
		{"responseBodyAccess=On", ctlResponseBodyAccess, "On", variables.Unknown, ""},
		{"responseBodyLimit=100", ctlResponseBodyLimit, "100", variables.Unknown, ""},
		{"ruleEngine=On", ctlRuleEngine, "On", variables.Unknown, ""},
		{"ruleRemoveById=1", ctlRuleRemoveByID, "1", variables.Unknown, ""},
		{"ruleRemoveByMsg=MY_MSG", ctlRuleRemoveByMsg, "MY_MSG", variables.Unknown, ""},
		{"ruleRemoveByTag=MY_TAG", ctlRuleRemoveByTag, "MY_TAG", variables.Unknown, ""},
		{"ruleRemoveTargetByMsg=MY_MSG;ARGS:user", ctlRuleRemoveTargetByMsg, "MY_MSG", variables.Args, "user"},
		{"ruleRemoveTargetById=2;REQUEST_FILENAME:", ctlRuleRemoveTargetByID, "2", variables.RequestFilename, ""},
	}
	for _, tCase := range tCases {
		testName, _, _ := strings.Cut(tCase.input, "=")
		t.Run(testName, func(t *testing.T) {
			action, value, collection, colKey, err := parseCtl(tCase.input)
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			if action != tCase.expectAction {
				t.Errorf("unexpected action, want: %d, have: %d", tCase.expectAction, action)
			}
			if value != tCase.expectValue {
				t.Errorf("unexpected value, want: %s, have: %s", tCase.expectValue, value)
			}
			if collection != tCase.expectCollection {
				t.Errorf("unexpected collection, want: %s, have: %s", tCase.expectCollection.Name(), collection.Name())
			}
			if colKey != tCase.expectKey {
				t.Errorf("unexpected key, want: %s, have: %s", tCase.expectKey, colKey)
			}
		})
	}

}
func TestCtlParseRange(t *testing.T) {
	rules := []*corazawaf.Rule{
		{
			RuleMetadata: corazarules.RuleMetadata{
				ID_: 5,
			},
		},
		{
			RuleMetadata: corazarules.RuleMetadata{
				ID_: 15,
			},
		},
	}

	tCases := []struct {
		_range              string
		expectedNumberOfIds int
		expectErr           bool
	}{
		{"1-2", 0, false},
		{"4-5", 1, false},
		{"4-15", 2, false},
		{"5", 1, false},
		{"", 0, true},
		{"test", 0, true},
		{"test-2", 0, true},
		{"2-test", 0, true},
		{"-", 0, true},
		{"4-5-15", 0, true},
	}
	for _, tCase := range tCases {
		t.Run(tCase._range, func(t *testing.T) {
			ints, err := rangeToInts(rules, tCase._range)
			if tCase.expectErr && err == nil {
				t.Error("expected error for range")
			}

			if !tCase.expectErr && err != nil {
				t.Errorf("unexpected error for range: %s", err.Error())
			}

			if !tCase.expectErr && len(ints) != tCase.expectedNumberOfIds {
				t.Error("unexpected number of ids")
			}
		})
	}
}

func TestParseOnOff(t *testing.T) {
	tCases := []struct {
		val         string
		expectedVal bool
		expectedOK  bool
	}{
		{"on", true, true},
		{"ON", true, true},
		{"On", true, true},
		{"off", false, true},
		{"OFF", false, true},
		{"Off", false, true},
		{"Whatever", false, false},
	}

	for _, tCase := range tCases {
		t.Run(tCase.val, func(t *testing.T) {
			val, ok := parseOnOff(tCase.val)
			if want, have := tCase.expectedOK, ok; want != have {
				t.Errorf("unexpected OK, want: %t, have: %t", want, have)
			}
			if want, have := tCase.expectedVal, val; want != have {
				t.Errorf("unexpected value, want: %t, have: %t", want, have)
			}
		})
	}
}
