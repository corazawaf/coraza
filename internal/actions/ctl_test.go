// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"bytes"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
	"github.com/stretchr/testify/require"
)

func TestCtl(t *testing.T) {
	tests := map[string]struct {
		input     string
		prepareTX func(tx *corazawaf.Transaction)
		checkTX   func(t *testing.T, tx *corazawaf.Transaction, logEntry string)
	}{
		"ruleRemoveTargetById": {
			input: "ruleRemoveTargetById=123",
		},
		"ruleRemoveTargetByTag": {
			input: "ruleRemoveTargetByTag=tag1",
		},
		"ruleRemoveTargetByMsg": {
			input: "ruleRemoveTargetByMsg=somethingWentWrong",
		},
		"auditEngine incorrect": {
			input: "auditEngine=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "Invalid status")
			},
		},
		"auditEngine successfully": {
			input: "auditEngine=Off",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Equal(t, types.AuditEngineOff, tx.AuditEngine)
			},
		},
		"auditLogParts": {
			input: "auditLogParts=ABZ",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Equal(t, types.AuditLogPartRequestHeaders, tx.AuditLogParts[1])
			},
		},
		"forceRequestBodyVariable incorrect": {
			input: "forceRequestBodyVariable=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "X")
			},
		},
		"forceRequestBodyVariable successfully": {
			input: "forceRequestBodyVariable=On",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.True(t, tx.ForceRequestBodyVariable)
			},
		},
		"requestBodyAccess incorrect": {
			input: "requestBodyAccess=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "[ERROR] Unknown toggle")
			},
		},
		"requestBodyAccess too late": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
				_, _ = tx.ProcessRequestBody()
			},
			input: "requestBodyAccess=On",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "[WARN] Cannot change request body access after request headers phase")
			},
		},
		"requestBodyAccess successfully": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
			},
			input: "requestBodyAccess=On",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.True(t, tx.RequestBodyAccess)
			},
		},
		"requestBodyProcessor too late": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
				_, _ = tx.ProcessRequestBody()
			},
			input: "requestBodyProcessor=JSON",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "[WARN] Cannot change request body processor after request headers phase")
			},
		},
		"requestBodyProcessor successfully": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
			},
			input: "requestBodyProcessor=XML",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Equal(t, "XML", tx.Variables().RequestBodyProcessor().Get())
			},
		},
		"requestBodyLimit incorrect": {
			input: "requestBodyLimit=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "[ERROR] Invalid limit")
			},
		},
		"requestBodyLimit too late": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
				_, _ = tx.ProcessRequestBody()
			},
			input: "requestBodyLimit=12345",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "[WARN] Cannot change request body limit after request headers phase")
			},
		},
		"requestBodyLimit successfully": {
			input: "requestBodyLimit=12345",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Equal(t, int64(12345), tx.RequestBodyLimit)
			},
		},
		"ruleEngine incorrect": {
			input: "ruleEngine=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "Invalid status")
			},
		},
		"ruleEngine successfully": {
			input: "ruleEngine=Off",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Equal(t, types.RuleEngineOff, tx.RuleEngine)
			},
		},
		"ruleRemoveById": {
			input: "ruleRemoveById=123",
		},
		"ruleRemoveById range": {
			input: "ruleRemoveById=1-3",
		},
		"ruleRemoveById incorrect": {
			input: "ruleRemoveById=W",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "[ERROR] Invalid rule ID")
			},
		},
		"ruleRemoveById range incorrect": {
			input: "ruleRemoveById=a-2",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "[ERROR] Invalid range")
			},
		},
		"ruleRemoveByMsg": {
			input: "ruleRemoveByMsg=somethingWentWrong",
		},
		"ruleRemoveByTag": {
			input: "ruleRemoveByTag=tag1",
		},
		"requestBodyProcessor": {
			input: "requestBodyProcessor=XML",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Equal(t, "XML", tx.Variables().RequestBodyProcessor().Get())
			},
		},
		"responseBodyAccess incorrect": {
			input: "responseBodyAccess=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "[ERROR] Unknown toggle")
			},
		},
		"responseBodyAccess too late": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
				_, _ = tx.ProcessRequestBody()
				tx.ProcessResponseHeaders(200, "HTTP/1.1")
				_, _ = tx.ProcessResponseBody()
			},
			input: "responseBodyAccess=On",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "[WARN] Cannot change response body access after response headers phase")
			},
		},
		"responseBodyAccess successfully": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
			},
			input: "responseBodyAccess=On",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.True(t, tx.ResponseBodyAccess)
			},
		},
		"responseBodyLimit successfully": {
			input: "responseBodyLimit=12345",
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
				_, _ = tx.ProcessRequestBody()
				tx.ProcessRequestHeaders()
			},
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Equal(t, int64(12345), tx.ResponseBodyLimit)
			},
		},
		"responseBodyLimit too late": {
			input: "responseBodyLimit=12345",
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
				_, _ = tx.ProcessRequestBody()
				tx.ProcessResponseHeaders(200, "HTTP/1.1")
				_, _ = tx.ProcessResponseBody()
			},
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "[WARN] Cannot change response body access after response headers phase")
			},
		},
		"responseBodyLimit incorrect": {
			input: "responseBodyLimit=a",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "[ERROR] Invalid limit")
			},
		},
		"responseBodyProcessor successfully": {
			input: "responseBodyProcessor=XML",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Equal(t, "XML", tx.Variables().ResponseBodyProcessor().Get())
			},
		},
		"responseBodyProcessor too late": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
				_, _ = tx.ProcessRequestBody()
				tx.ProcessResponseHeaders(200, "HTTP/1.1")
				_, _ = tx.ProcessResponseBody()
			},
			input: "responseBodyProcessor=XML",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "[WARN] Cannot change response body access after response headers phase")
			},
		},
		"forceResponseBodyVariable incorrect": {
			input: "forceResponseBodyVariable=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "X")
			},
		},
		"forceResponseBodyVariable successfully": {
			input: "forceResponseBodyVariable=On",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.True(t, tx.ForceResponseBodyVariable)
			},
		},
		"debugLogLevel incorrect": {
			input: "debugLogLevel=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				require.Contains(t, logEntry, "[ERROR] Invalid log level")
			},
		},
		"debugLogLevel successfully": {
			input: "debugLogLevel=1",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			logsBuf := &bytes.Buffer{}
			defer logsBuf.Reset()

			logger := debuglog.Default().
				WithLevel(debuglog.LevelWarn).
				WithOutput(logsBuf)

			waf := corazawaf.NewWAF()
			waf.Logger = logger
			r := corazawaf.NewRule()
			r.ID_ = 1
			r.LogID_ = "1"
			err := waf.Rules.Add(r)
			require.NoError(t, err, "failed to add rule")

			a := ctl()
			require.NoError(t, a.Init(r, test.input), "failed to init ctl")

			tx := waf.NewTransaction()
			if test.prepareTX != nil {
				test.prepareTX(tx)
			}
			a.Evaluate(r, tx)

			if test.checkTX == nil {
				// TODO(jcchavezs): for some tests we can't do any assertion
				// without going too deep into the implementation details.
				// t.SkipNow() can't be used because tinygo doesn't support it.
				// https://github.com/tinygo-org/tinygo/blob/release/src/testing/testing.go#L246
				return
			} else {
				test.checkTX(t, tx, logsBuf.String())
			}
		})
	}
}

func TestParseCtl(t *testing.T) {
	t.Run("invalid ctl", func(t *testing.T) {
		ctl, _, _, _, err := parseCtl("invalid")
		require.Error(t, err)

		require.Equal(t, ctlUnknown, ctl)
	})

	t.Run("malformed ctl", func(t *testing.T) {
		ctl, _, _, _, err := parseCtl("unknown=")
		require.Error(t, err)

		require.Equal(t, ctlUnknown, ctl)
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
		{"requestBodyAccess=On", ctlRequestBodyAccess, "On", variables.Unknown, ""},
		{"requestBodyLimit=100", ctlRequestBodyLimit, "100", variables.Unknown, ""},
		{"requestBodyProcessor=JSON", ctlRequestBodyProcessor, "JSON", variables.Unknown, ""},
		{"forceRequestBodyVariable=On", ctlForceRequestBodyVariable, "On", variables.Unknown, ""},
		{"responseBodyAccess=On", ctlResponseBodyAccess, "On", variables.Unknown, ""},
		{"responseBodyLimit=100", ctlResponseBodyLimit, "100", variables.Unknown, ""},
		{"responseBodyProcessor=JSON", ctlResponseBodyProcessor, "JSON", variables.Unknown, ""},
		{"forceResponseBodyVariable=On", ctlForceResponseBodyVariable, "On", variables.Unknown, ""},
		{"ruleEngine=On", ctlRuleEngine, "On", variables.Unknown, ""},
		{"ruleRemoveById=1", ctlRuleRemoveByID, "1", variables.Unknown, ""},
		{"ruleRemoveById=1-9", ctlRuleRemoveByID, "1-9", variables.Unknown, ""},
		{"ruleRemoveByMsg=MY_MSG", ctlRuleRemoveByMsg, "MY_MSG", variables.Unknown, ""},
		{"ruleRemoveByTag=MY_TAG", ctlRuleRemoveByTag, "MY_TAG", variables.Unknown, ""},
		{"ruleRemoveTargetByMsg=MY_MSG;ARGS:user", ctlRuleRemoveTargetByMsg, "MY_MSG", variables.Args, "user"},
		{"ruleRemoveTargetById=2;REQUEST_FILENAME:", ctlRuleRemoveTargetByID, "2", variables.RequestFilename, ""},
	}
	for _, tCase := range tCases {
		testName, _, _ := strings.Cut(tCase.input, "=")
		t.Run(testName, func(t *testing.T) {
			action, value, collection, colKey, err := parseCtl(tCase.input)
			require.NoError(t, err)
			require.Equal(t, tCase.expectAction, action)
			require.Equal(t, tCase.expectValue, value)
			require.Equal(t, tCase.expectCollection, collection)
			require.Equal(t, tCase.expectKey, colKey)
		})
	}

}
func TestCtlParseRange(t *testing.T) {
	rules := []corazawaf.Rule{
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
			if tCase.expectErr {
				require.Error(t, err, "expected error for range")
			} else {
				require.NoError(t, err)
				require.Equal(t, tCase.expectedNumberOfIds, len(ints))
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
			require.Equal(t, tCase.expectedOK, ok)
			require.Equal(t, tCase.expectedVal, val)
		})
	}
}
