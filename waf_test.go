// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"errors"
	"reflect"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/require"
)

// wafWithRules mirrors experimental.WAFWithRules for testing without import cycle.
type wafWithRules interface {
	RulesCount() int
}

func TestRequestBodyLimit(t *testing.T) {
	testCases := map[string]struct {
		expectedErr   error
		limit         int
		inMemoryLimit int
	}{
		"empty limit": {
			limit:         0,
			inMemoryLimit: 2,
			expectedErr:   errors.New("request body limit should be bigger than 0"),
		},
		"empty memory limit": {
			limit:         2,
			inMemoryLimit: 0,
			expectedErr:   errors.New("request body memory limit should be bigger than 0"),
		},
		"memory limit bigger than limit": {
			limit:         5,
			inMemoryLimit: 9,
			expectedErr:   errors.New("request body limit should be at least the memory limit"),
		},
		"limit bigger than the hard limit": {
			limit:       1073741825,
			expectedErr: errors.New("request body limit should be at most 1GiB"),
		},
		"right limits": {
			limit:         100,
			inMemoryLimit: 50,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := NewWAFConfig().(*wafConfig)
			cfg.requestBodyLimit = &tCase.limit
			cfg.requestBodyInMemoryLimit = &tCase.inMemoryLimit

			_, err := NewWAF(cfg)
			if tCase.expectedErr == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.EqualError(t, err, tCase.expectedErr.Error())
			}
		})
	}
}

func TestResponseBodyLimit(t *testing.T) {
	testCases := map[string]struct {
		expectedErr error
		limit       int
	}{
		"empty limit": {
			limit:       0,
			expectedErr: errors.New("response body limit should be bigger than 0"),
		},
		"limit bigger than the hard limit": {
			limit:       1073741825,
			expectedErr: errors.New("response body limit should be at most 1GiB"),
		},
		"right limit": {
			limit: 100,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := NewWAFConfig().(*wafConfig)
			cfg.responseBodyLimit = &tCase.limit

			_, err := NewWAF(cfg)
			if tCase.expectedErr == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.EqualError(t, err, tCase.expectedErr.Error())
			}
		})
	}
}

type testAuditLogWriter struct {
	plugintypes.AuditLogWriter
}

func (*testAuditLogWriter) Init(plugintypes.AuditLogConfig) error {
	return nil
}

func TestPopulateAuditLog(t *testing.T) {
	writer := &testAuditLogWriter{}

	testCases := map[string]struct {
		config *wafConfig
		check  func(*testing.T, *corazawaf.WAF)
	}{
		"empty config": {
			config: &wafConfig{},
			check:  func(*testing.T, *corazawaf.WAF) {},
		},
		"with relevant only": {
			config: &wafConfig{
				auditLog: &auditLogConfig{
					relevantOnly: true,
				},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				require.Equal(t, types.AuditEngineRelevantOnly, waf.AuditEngine, "expected AuditLogRelevantOnly to be true")
			},
		},
		"with parts": {
			config: &wafConfig{
				auditLog: &auditLogConfig{
					parts: []types.AuditLogPart{
						types.AuditLogPartRequestHeaders,
						types.AuditLogPartResponseBody,
					},
				},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				require.Equal(t, types.AuditLogParts([]types.AuditLogPart{
					types.AuditLogPartRequestHeaders,
					types.AuditLogPartResponseBody,
				}), waf.AuditLogParts, "unexpected AuditLogParts")
			},
		},
		"with audit log writer": {
			config: &wafConfig{
				auditLog: &auditLogConfig{writer: writer},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				require.False(t, reflect.DeepEqual(waf.AuditLogWriter(), &writer), "expected AuditLogWriter to be set")
			},
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			waf := &corazawaf.WAF{}
			populateAuditLog(waf, tCase.config)
			tCase.check(t, waf)
		})
	}
}

func TestDetectionOnlyEnforcesProcessPartialBodyLimitActions(t *testing.T) {
	waf, err := NewWAF(NewWAFConfig().WithDirectives(`
		SecRuleEngine DetectionOnly
		SecRequestBodyAccess On
		SecRequestBodyLimitAction Reject
		SecResponseBodyAccess On
		SecResponseBodyLimitAction Reject
	`))
	require.NoError(t, err)

	w := waf.(wafWrapper).waf
	require.Equal(t, types.BodyLimitActionProcessPartial, w.RequestBodyLimitAction, "expected RequestBodyLimitAction to be ProcessPartial in DetectionOnly mode")
	require.Equal(t, types.BodyLimitActionProcessPartial, w.ResponseBodyLimitAction, "expected ResponseBodyLimitAction to be ProcessPartial in DetectionOnly mode")
}

func TestRulesCount(t *testing.T) {
	waf, err := NewWAF(NewWAFConfig())
	require.NoError(t, err)

	rules, ok := waf.(wafWithRules)
	require.True(t, ok, "WAF does not implement WAFWithRules")
	require.Equal(t, 0, rules.RulesCount(), "expected 0 rules")

	waf, err = NewWAF(NewWAFConfig().
		WithDirectives(`SecRule REMOTE_ADDR "127.0.0.1" "id:1,phase:1,deny,status:403"`).
		WithDirectives(`SecRule REQUEST_URI "/test" "id:2,phase:1,deny,status:403"`))
	require.NoError(t, err)

	rules, ok = waf.(wafWithRules)
	require.True(t, ok, "WAF does not implement WAFWithRules")
	require.Equal(t, 2, rules.RulesCount(), "expected 2 rules")
}
