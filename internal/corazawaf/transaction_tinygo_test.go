// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package corazawaf

// func TestRequestBodyTinyGo(t *testing.T) {
// 	const (
// 		urlencodedBody    = "some=result&second=data"
// 		urlencodedBodyLen = len(urlencodedBody)
// 	)

// 	testCases := []struct {
// 		name                   string
// 		requestBodyLimit       int
// 		requestBodyMemoryLimit int
// 		requestBodyLimitAction types.BodyLimitAction
// 		shouldInterrupt        bool
// 	}{
// 		{
// 			name:                   "memory buffer (equal to limit) not reached",
// 			requestBodyMemoryLimit: urlencodedBodyLen + 2,
// 			requestBodyLimit:       urlencodedBodyLen + 2,
// 			requestBodyLimitAction: types.BodyLimitActionReject,
// 		},
// 		{
// 			name:                   "memory buffer (equal to limit) rejects",
// 			requestBodyMemoryLimit: urlencodedBodyLen / 2,
// 			requestBodyLimit:       urlencodedBodyLen / 2,
// 			requestBodyLimitAction: types.BodyLimitActionReject,
// 			shouldInterrupt:        true,
// 		},
// 		{
// 			name:                   "memory buffer and limit partial processing",
// 			requestBodyMemoryLimit: urlencodedBodyLen - 1,
// 			requestBodyLimit:       urlencodedBodyLen - 1,
// 			requestBodyLimitAction: types.BodyLimitActionProcessPartial,
// 		},
// 	}

// 	for _, testCase := range testCases {
// 		t.Run(testCase.name, func(t *testing.T) {
// 			waf := NewWAF()
// 			waf.RuleEngine = types.RuleEngineOn
// 			waf.RequestBodyAccess = true
// 			waf.RequestBodyLimit = int64(testCase.requestBodyLimit)
// 			waf.RequestBodyInMemoryLimit = int64(testCase.requestBodyMemoryLimit)
// 			waf.RequestBodyLimitAction = testCase.requestBodyLimitAction

// 			tx := waf.NewTransaction()
// 			tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
// 			if _, err := tx.RequestBodyBuffer.Write([]byte(urlencodedBody)); err != nil {
// 				t.Errorf("Failed to write body buffer: %s", err.Error())
// 			}

// 			tx.ProcessRequestHeaders()
// 			if _, err := tx.ProcessRequestBody(); err != nil {
// 				t.Errorf("Failed to process request body: %s", err.Error())
// 			}

// 			if testCase.shouldInterrupt {
// 				if tx.interruption == nil {
// 					t.Error("Expected interruption, got nil")
// 				}
// 			} else {
// 				val := tx.variables.argsPost.Get("some")
// 				if len(val) != 1 || val[0] != "result" {
// 					t.Errorf("Failed to set urlencoded POST data with arguments: \"%s\"", strings.Join(val, "\", \""))
// 				}
// 			}

// 			_ = tx.Close()
// 		})
// 	}
// }
