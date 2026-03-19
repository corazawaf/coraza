// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"bytes"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
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
		"ruleRemoveTargetById range": {
			// Rule 1 is in WAF; range 1-5 should match it without error
			input: "ruleRemoveTargetById=1-5;ARGS:test",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToNotContain := "Invalid range"; strings.Contains(logEntry, wantToNotContain) {
					t.Errorf("unexpected error in log: %q", logEntry)
				}
			},
		},
		"ruleRemoveTargetById regex key": {
			// Rule 1 is in WAF; the regex /^test.*/ should remove matching ARGS targets
			input: "ruleRemoveTargetById=1;ARGS:/^test.*/",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if strings.Contains(logEntry, "Invalid") || strings.Contains(logEntry, "invalid") {
					t.Errorf("unexpected error in log: %q", logEntry)
				}
			},
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
				if wantToContain, have := "Invalid status", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"auditEngine successfully": {
			input: "auditEngine=Off",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if tx.AuditEngine != types.AuditEngineOff {
					t.Error("Failed to disable audit log")
				}
			},
		},
		"auditLogParts": {
			input: "auditLogParts=ABZ",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if want, have := types.AuditLogPartRequestHeaders, tx.AuditLogParts[1]; want != have {
					t.Errorf("Failed to set audit log parts, want %s, have %s", string(want), string(have))
				}
			},
		},
		"forceRequestBodyVariable incorrect": {
			input: "forceRequestBodyVariable=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToContain, have := "X", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"forceRequestBodyVariable successfully": {
			input: "forceRequestBodyVariable=On",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if want, have := true, tx.ForceRequestBodyVariable; want != have {
					t.Errorf("Failed to set forceRequestBodyVariable, want %t, have %t", want, have)
				}
			},
		},
		"requestBodyAccess incorrect": {
			input: "requestBodyAccess=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToContain, have := "[ERROR] Unknown toggle", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"requestBodyAccess too late": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
				_, _ = tx.ProcessRequestBody()
			},
			input: "requestBodyAccess=On",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToContain, have := "[WARN] Cannot change request body access after request headers phase", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"requestBodyAccess successfully": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
			},
			input: "requestBodyAccess=On",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if want, have := true, tx.RequestBodyAccess; want != have {
					t.Errorf("Failed to set requestBodyAccess, want %t, have %t", want, have)
				}
			},
		},
		"requestBodyProcessor too late": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
				_, _ = tx.ProcessRequestBody()
			},
			input: "requestBodyProcessor=JSON",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToContain, have := "[WARN] Cannot change request body processor after request headers phase", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"requestBodyProcessor successfully": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
			},
			input: "requestBodyProcessor=XML",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if want, have := "XML", tx.Variables().RequestBodyProcessor().Get(); want != have {
					t.Errorf("Failed to set requestBodyProcessor, want %s, have %s", want, have)
				}
			},
		},
		"requestBodyLimit incorrect": {
			input: "requestBodyLimit=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToContain, have := "[ERROR] Invalid limit", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"requestBodyLimit too late": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
				_, _ = tx.ProcessRequestBody()
			},
			input: "requestBodyLimit=12345",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToContain, have := "[WARN] Cannot change request body limit after request headers phase", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"requestBodyLimit successfully": {
			input: "requestBodyLimit=12345",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if want, have := int64(12345), tx.RequestBodyLimit; want != have {
					t.Errorf("Failed to set requestBodyLimit, want %d, have %d", want, have)
				}
			},
		},
		"ruleEngine incorrect": {
			input: "ruleEngine=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToContain, have := "Invalid status", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"ruleEngine successfully": {
			input: "ruleEngine=Off",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if want, have := types.RuleEngineOff, tx.RuleEngine; want != have {
					t.Errorf("Failed to set ruleEngine, want %s, have %s", want, have)
				}
			},
		},
		"ruleRemoveById": {
			input: "ruleRemoveById=123",
		},
		"ruleRemoveById range": {
			input: "ruleRemoveById=1-3",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if len(tx.GetRuleRemoveByIDRanges()) != 1 {
					t.Errorf("expected 1 range entry, got %d", len(tx.GetRuleRemoveByIDRanges()))
					return
				}
				rng := tx.GetRuleRemoveByIDRanges()[0]
				if rng[0] != 1 || rng[1] != 3 {
					t.Errorf("unexpected range [%d, %d], want [1, 3]", rng[0], rng[1])
				}
			},
		},
		"ruleRemoveById incorrect": {
			input: "ruleRemoveById=W",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToContain, have := "[ERROR] Invalid rule ID", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"ruleRemoveById range incorrect": {
			input: "ruleRemoveById=a-2",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToContain, have := "[ERROR] Invalid range", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
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
				if want, have := tx.Variables().RequestBodyProcessor().Get(), "XML"; want != have {
					t.Errorf("failed to set requestBodyProcessor, want %s, have %s", want, have)
				}
			},
		},
		"responseBodyAccess incorrect": {
			input: "responseBodyAccess=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToContain, have := "[ERROR] Unknown toggle", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
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
				if wantToContain, have := "[WARN] Cannot change response body access after response headers phase", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"responseBodyAccess successfully": {
			prepareTX: func(tx *corazawaf.Transaction) {
				tx.ProcessRequestHeaders()
			},
			input: "responseBodyAccess=On",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if want, have := true, tx.ResponseBodyAccess; want != have {
					t.Errorf("Failed to set responseBodyAccess, want %t, have %t", want, have)
				}
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
				if tx.ResponseBodyLimit != 12345 {
					t.Errorf("Failed to set response body limit, want %d, have %d", 12345, tx.ResponseBodyLimit)
				}
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
				if wantToContain, have := "[WARN] Cannot change response body access after response headers phase", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"responseBodyLimit incorrect": {
			input: "responseBodyLimit=a",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToContain, have := "[ERROR] Invalid limit", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"responseBodyProcessor successfully": {
			input: "responseBodyProcessor=XML",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if want, have := tx.Variables().ResponseBodyProcessor().Get(), "XML"; want != have {
					t.Errorf("failed to set requestBodyProcessor, want %s, have %s", want, have)
				}
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
				if wantToContain, have := "[WARN] Cannot change response body access after response headers phase", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"forceResponseBodyVariable incorrect": {
			input: "forceResponseBodyVariable=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToContain, have := "X", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
			},
		},
		"forceResponseBodyVariable successfully": {
			input: "forceResponseBodyVariable=On",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if want, have := true, tx.ForceResponseBodyVariable; want != have {
					t.Errorf("Failed to set forceResponseBodyVariable, want %t, have %t", want, have)
				}
			},
		},
		"debugLogLevel incorrect": {
			input: "debugLogLevel=X",
			checkTX: func(t *testing.T, tx *corazawaf.Transaction, logEntry string) {
				if wantToContain, have := "[ERROR] Invalid log level", logEntry; !strings.Contains(have, wantToContain) {
					t.Errorf("Failed to log entry, want to contain %q, have %q", wantToContain, have)
				}
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
			if err != nil {
				t.Fatalf("failed to add rule: %s", err.Error())
			}

			a := ctl()
			if err := a.Init(r, test.input); err != nil {
				t.Fatalf("failed to init ctl: %s", err.Error())
			}

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
		ctl, _, _, _, _, err := parseCtl("invalid", nil)
		if err == nil {
			t.Errorf("expected error, got nil")
		}

		if ctl != ctlUnknown {
			t.Errorf("expected ctlUnknown, got %d", ctl)
		}
	})

	t.Run("malformed ctl", func(t *testing.T) {
		ctl, _, _, _, _, err := parseCtl("unknown=", nil)
		if err == nil {
			t.Errorf("expected error, got nil")
		}

		if ctl != ctlUnknown {
			t.Errorf("expected ctlUnknown, got %d", ctl)
		}
	})

	t.Run("invalid regex in colKey", func(t *testing.T) {
		_, _, _, _, _, err := parseCtl("ruleRemoveTargetById=1;ARGS:/[invalid/", nil)
		if err == nil {
			t.Errorf("expected error for invalid regex, got nil")
		}
	})

	t.Run("empty regex pattern in colKey", func(t *testing.T) {
		_, _, _, _, _, err := parseCtl("ruleRemoveTargetById=1;ARGS://", nil)
		if err == nil {
			t.Errorf("expected error for empty regex pattern, got nil")
		}
	})

	t.Run("escaped slash not treated as regex", func(t *testing.T) {
		_, _, _, key, rx, err := parseCtl(`ruleRemoveTargetById=1;ARGS:/user\/`, nil)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		if rx != nil {
			t.Errorf("expected nil regex for escaped-slash key, got: %s", rx.String())
		}
		if key != `/user\/` {
			t.Errorf("unexpected key, want %q, have %q", `/user\/`, key)
		}
	})

	tCases := []struct {
		input            string
		expectAction     ctlFunctionType
		expectValue      string
		expectCollection variables.RuleVariable
		expectKey        string
		expectKeyRx      string
	}{
		{"auditEngine=On", ctlAuditEngine, "On", variables.Unknown, "", ""},
		{"auditLogParts=A", ctlAuditLogParts, "A", variables.Unknown, "", ""},
		{"requestBodyAccess=On", ctlRequestBodyAccess, "On", variables.Unknown, "", ""},
		{"requestBodyLimit=100", ctlRequestBodyLimit, "100", variables.Unknown, "", ""},
		{"requestBodyProcessor=JSON", ctlRequestBodyProcessor, "JSON", variables.Unknown, "", ""},
		{"forceRequestBodyVariable=On", ctlForceRequestBodyVariable, "On", variables.Unknown, "", ""},
		{"responseBodyAccess=On", ctlResponseBodyAccess, "On", variables.Unknown, "", ""},
		{"responseBodyLimit=100", ctlResponseBodyLimit, "100", variables.Unknown, "", ""},
		{"responseBodyProcessor=JSON", ctlResponseBodyProcessor, "JSON", variables.Unknown, "", ""},
		{"forceResponseBodyVariable=On", ctlForceResponseBodyVariable, "On", variables.Unknown, "", ""},
		{"ruleEngine=On", ctlRuleEngine, "On", variables.Unknown, "", ""},
		{"ruleRemoveById=1", ctlRuleRemoveByID, "1", variables.Unknown, "", ""},
		{"ruleRemoveById=1-9", ctlRuleRemoveByID, "1-9", variables.Unknown, "", ""},
		{"ruleRemoveByMsg=MY_MSG", ctlRuleRemoveByMsg, "MY_MSG", variables.Unknown, "", ""},
		{"ruleRemoveByTag=MY_TAG", ctlRuleRemoveByTag, "MY_TAG", variables.Unknown, "", ""},
		{"ruleRemoveTargetByMsg=MY_MSG;ARGS:user", ctlRuleRemoveTargetByMsg, "MY_MSG", variables.Args, "user", ""},
		{"ruleRemoveTargetById=2;REQUEST_FILENAME:", ctlRuleRemoveTargetByID, "2", variables.RequestFilename, "", ""},
		{"ruleRemoveTargetById=2;ARGS:/^json\\.\\d+\\.description$/", ctlRuleRemoveTargetByID, "2", variables.Args, "", `^json\.\d+\.description$`},
	}
	for _, tCase := range tCases {
		testName, _, _ := strings.Cut(tCase.input, "=")
		t.Run(testName, func(t *testing.T) {
			action, value, collection, colKey, colKeyRx, err := parseCtl(tCase.input, nil)
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
			if tCase.expectKeyRx == "" {
				if colKeyRx != nil {
					t.Errorf("unexpected non-nil regex, have: %s", colKeyRx.String())
				}
			} else {
				if colKeyRx == nil {
					t.Errorf("expected non-nil regex matching %q, got nil", tCase.expectKeyRx)
				} else if colKeyRx.String() != tCase.expectKeyRx {
					t.Errorf("unexpected regex, want: %s, have: %s", tCase.expectKeyRx, colKeyRx.String())
				}
			}
		})
	}

}
func TestCtlParseIDOrRange(t *testing.T) {
	tCases := []struct {
		input       string
		expectStart int
		expectEnd   int
		expectErr   bool
	}{
		{"1-2", 1, 2, false},
		{"4-5", 4, 5, false},
		{"4-15", 4, 15, false},
		{"5", 5, 5, false},
		{"", 0, 0, true},
		{"test", 0, 0, true},
		{"test-2", 0, 0, true},
		{"2-test", 0, 0, true},
		{"-", 0, 0, true},
		{"4-5-15", 0, 0, true},
	}
	for _, tCase := range tCases {
		t.Run(tCase.input, func(t *testing.T) {
			start, end, err := parseIDOrRange(tCase.input)
			if tCase.expectErr && err == nil {
				t.Error("expected error for input")
			}

			if !tCase.expectErr && err != nil {
				t.Errorf("unexpected error for input: %s", err.Error())
			}

			if !tCase.expectErr {
				if start != tCase.expectStart {
					t.Errorf("unexpected start, want %d, have %d", tCase.expectStart, start)
				}
				if end != tCase.expectEnd {
					t.Errorf("unexpected end, want %d, have %d", tCase.expectEnd, end)
				}
			}
		})
	}
}

func TestCtlParseRange(t *testing.T) {
	tCases := []struct {
		input       string
		expectStart int
		expectEnd   int
		expectErr   bool
	}{
		{"1-2", 1, 2, false},
		{"4-15", 4, 15, false},
		{"5-5", 5, 5, false},
		{"test-2", 0, 0, true},
		{"2-test", 0, 0, true},
		{"5-4", 0, 0, true}, // start > end
		{"-", 0, 0, true},
		{"nodash", 0, 0, true}, // no range separator
	}
	for _, tCase := range tCases {
		t.Run(tCase.input, func(t *testing.T) {
			start, end, err := parseRange(tCase.input)
			if tCase.expectErr && err == nil {
				t.Error("expected error for input")
			}

			if !tCase.expectErr && err != nil {
				t.Errorf("unexpected error for input: %s", err.Error())
			}

			if !tCase.expectErr {
				if start != tCase.expectStart {
					t.Errorf("unexpected start, want %d, have %d", tCase.expectStart, start)
				}
				if end != tCase.expectEnd {
					t.Errorf("unexpected end, want %d, have %d", tCase.expectEnd, end)
				}
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
