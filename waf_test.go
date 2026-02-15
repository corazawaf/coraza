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
				require.Equal(t, tCase.expectedErr.Error(), err.Error())
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
				require.Equal(t, tCase.expectedErr.Error(), err.Error())
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
				require.Equal(t, types.AuditEngineRelevantOnly, waf.AuditEngine)
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
				want := []types.AuditLogPart{
					types.AuditLogPartRequestHeaders,
					types.AuditLogPartResponseBody,
				}
				require.Len(t, waf.AuditLogParts, len(want))
			},
		},
		"with audit log writer": {
			config: &wafConfig{
				auditLog: &auditLogConfig{writer: writer},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				require.False(t, reflect.DeepEqual(waf.AuditLogWriter(), &writer))
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
