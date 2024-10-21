// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestTxSettersMultipart(t *testing.T) {
	tx := makeTransactionMultipart(t)
	exp := map[string]string{
		"%{request_headers.x-test-header}": "test456",
		"%{request_method}":                "POST",
		"%{ARGS_GET.id}":                   "123",
		"%{request_cookies.test}":          "123",
		"%{args_post.testfield}":           "456",
		"%{args.testfield}":                "456",
		"%{request_line}":                  "POST /testurl.php?id=123&b=456 HTTP/1.1",
		"%{query_string}":                  "id=123&b=456",
		"%{request_filename}":              "/testurl.php",
		"%{request_protocol}":              "HTTP/1.1",
		"%{request_uri}":                   "/testurl.php?id=123&b=456",
		"%{request_uri_raw}":               "/testurl.php?id=123&b=456",
		"%{files_names}":                   "file1",
		"%{files_combined_size}":           "72",
		"%{files_sizes.a.txt}":             "19",
	}

	validateMacroExpansion(exp, tx, t)
}

func TestTxSetters(t *testing.T) {
	tx := makeTransaction(t)
	exp := map[string]string{
		"%{request_headers.x-test-header}": "test456",
		"%{request_method}":                "POST",
		"%{ARGS_GET.id}":                   "123",
		"%{request_cookies.test}":          "123",
		"%{args_post.testfield}":           "456",
		"%{args.testfield}":                "456",
		"%{request_line}":                  "POST /testurl.php?id=123&b=456 HTTP/1.1",
		"%{query_string}":                  "id=123&b=456",
		"%{request_filename}":              "/testurl.php",
		"%{request_protocol}":              "HTTP/1.1",
		"%{request_uri}":                   "/testurl.php?id=123&b=456",
		"%{request_uri_raw}":               "/testurl.php?id=123&b=456",
	}

	validateMacroExpansion(exp, tx, t)
}
func TestTxMultipart(t *testing.T) {
	tx := NewWAF().NewTransaction()
	body := []string{
		"-----------------------------9051914041544843365972754266",
		"Content-Disposition: form-data; name=\"text\"",
		"",
		"test-value",
		"-----------------------------9051914041544843365972754266",
		"Content-Disposition: form-data; name=\"file1\"; filename=\"a.html\"",
		"Content-Type: text/html",
		"",
		"<!DOCTYPE html><title>Content of a.html.</title>",
		"",
		"-----------------------------9051914041544843365972754266--",
	}
	data := strings.Join(body, "\r\n")
	headers := []string{
		"POST / HTTP/1.1",
		"Host: localhost:8000",
		"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:29.0) Gecko/20100101 Firefox/29.0",
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language: en-US,en;q=0.5",
		"Accept-Encoding: gzip, deflate",
		"Connection: keep-alive",
		"Content-Type: multipart/form-data; boundary=---------------------------9051914041544843365972754266",
		fmt.Sprintf("Content-Length: %d", len(data)),
	}
	data = strings.Join(headers, "\r\n") + "\r\n\r\n" + data + "\r\n"
	tx.RequestBodyAccess = true
	tx.RequestBodyLimit = 9999999
	_, err := tx.ParseRequestReader(strings.NewReader(data))
	if err != nil {
		t.Fatal("Failed to parse multipart request: " + err.Error())
	}
	exp := map[string]string{
		"%{args_post.text}":      "test-value",
		"%{files_combined_size}": "60",
		"%{files}":               "a.html",
		"%{files_names}":         "file1",
	}

	validateMacroExpansion(exp, tx, t)

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxResponse(t *testing.T) {
	/*
		tx := NewWAF().NewTransaction()
		ht := []string{
			"HTTP/1.1 200 OK",
			"Content-Type: text/html",
			"Last-Modified: Mon, 14 Sep 2020 21:10:42 GMT",
			"Accept-Ranges: bytes",
			"ETag: \"0b5f480db8ad61:0\"",
			"Vary: Accept-Encoding",
			"Server: Microsoft-IIS/8.5",
			"Content-Security-Policy: default-src: https:; frame-ancestors 'self' X-Frame-Options: SAMEORIGIN",
			"Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
			"Date: Wed, 16 Sep 2020 14:14:09 GMT",
			"Connection: close",
			"Content-Length: 10",
			"",
			"testcontent",
		}
		data := strings.Join(ht, "\r\n")
		tx.ParseResponseString(nil, data)

		exp := map[string]string{
			"%{response_headers.content-length}": "10",
			"%{response_headers.server}":         "Microsoft-IIS/8.5",
		}

		validateMacroExpansion(exp, tx, t)
	*/
}

var requestBodyWriters = map[string]func(tx *Transaction, body string) (*types.Interruption, int, error){
	"WriteRequestBody": func(tx *Transaction, body string) (*types.Interruption, int, error) {
		return tx.WriteRequestBody([]byte(body))
	},
	"ReadRequestBodyFromKnownLen": func(tx *Transaction, body string) (*types.Interruption, int, error) {
		return tx.ReadRequestBodyFrom(strings.NewReader(body))
	},
	"ReadRequestBodyFromUnknownLen": func(tx *Transaction, body string) (*types.Interruption, int, error) {
		return tx.ReadRequestBodyFrom(struct{ io.Reader }{
			strings.NewReader(body),
		})
	},
}

func TestWriteRequestBody(t *testing.T) {
	const (
		urlencodedBody    = "some=result&second=data"
		urlencodedBodyLen = len(urlencodedBody)
	)

	testCases := []struct {
		name                            string
		requestBodyLimit                int
		requestBodyLimitAction          types.BodyLimitAction
		avoidRequestBodyLimitActionInit bool
		shouldInterrupt                 bool
		limitReached                    bool // If the limit is reached, INBOUND_DATA_ERROR should be set
	}{
		{
			name:                   "LimitNotReached",
			requestBodyLimit:       urlencodedBodyLen + 2,
			requestBodyLimitAction: types.BodyLimitAction(-1),
			limitReached:           false,
		},
		{
			name:                   "LimitReachedAndRejects",
			requestBodyLimit:       urlencodedBodyLen - 3,
			requestBodyLimitAction: types.BodyLimitActionReject,
			shouldInterrupt:        true,
			limitReached:           true,
		},
		{
			name:             "LimitReachedAndRejectsDefaultValue",
			requestBodyLimit: urlencodedBodyLen - 3,
			// Omitting requestBodyLimitAction defaults to Reject
			// requestBodyLimitAction: types.BodyLimitActionReject,
			avoidRequestBodyLimitActionInit: true,
			shouldInterrupt:                 true,
			limitReached:                    true,
		},
		{
			name:                   "LimitReachedAndPartialProcessing",
			requestBodyLimit:       urlencodedBodyLen - 3,
			requestBodyLimitAction: types.BodyLimitActionProcessPartial,
			limitReached:           true,
		},
	}

	urlencodedBodyLenThird := urlencodedBodyLen / 3
	bodyChunks := map[string][]string{
		"BodyInOneShot":     {urlencodedBody},
		"BodyInThreeChunks": {urlencodedBody[0:urlencodedBodyLenThird], urlencodedBody[urlencodedBodyLenThird : 2*urlencodedBodyLenThird], urlencodedBody[2*urlencodedBodyLenThird:]},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			for name, writeRequestBody := range requestBodyWriters {
				t.Run(name, func(t *testing.T) {
					for name, chunks := range bodyChunks {
						t.Run(name, func(t *testing.T) {
							waf := NewWAF()
							waf.RuleEngine = types.RuleEngineOn
							waf.RequestBodyAccess = true
							waf.RequestBodyLimit = int64(testCase.requestBodyLimit)
							if !testCase.avoidRequestBodyLimitActionInit {
								waf.RequestBodyLimitAction = testCase.requestBodyLimitAction
							}
							tx := waf.NewTransaction()
							tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")

							it := tx.ProcessRequestHeaders()
							if it != nil {
								t.Fatal("Unexpected interruption on headers")
							}

							var err error

							for _, c := range chunks {
								if it, _, err = writeRequestBody(tx, c); err != nil {
									t.Fatalf("Failed to write body buffer: %s", err.Error())
								}
							}
							if testCase.limitReached && tx.variables.inboundDataError.Get() != "1" {
								t.Fatalf("Expected INBOUND_DATA_ERROR to be set")
							}
							if testCase.shouldInterrupt {
								if it == nil {
									t.Fatal("Expected interruption, got nil")
								}
							} else {
								it, err := tx.ProcessRequestBody()
								if err != nil {
									t.Fatal(err)
								}

								if it != nil {
									t.Fatalf("Unexpected interruption")
								}

								val := tx.variables.argsPost.Get("some")
								if len(val) != 1 || val[0] != "result" {
									t.Fatalf("Failed to set urlencoded POST data with arguments: \"%s\"", strings.Join(val, "\", \""))
								}
							}

							if err := tx.Close(); err != nil {
								t.Fatalf("Failed to close transaction: %s", err.Error())
							}
						})
					}

				})
			}

		})
	}
}

func TestWriteRequestBodyOnLimitReached(t *testing.T) {
	testCases := map[string]struct {
		requestBodyLimitAction  types.BodyLimitAction
		preexistingInterruption *types.Interruption
	}{
		"reject": {
			requestBodyLimitAction: types.BodyLimitActionReject,
			preexistingInterruption: &types.Interruption{
				RuleID: 123,
			},
		},
		"partial processing": {
			requestBodyLimitAction: types.BodyLimitActionProcessPartial,
		},
	}

	for tName, tCase := range testCases {
		waf := NewWAF()
		waf.RuleEngine = types.RuleEngineOn
		waf.RequestBodyAccess = true
		waf.RequestBodyLimit = 2
		waf.RequestBodyLimitAction = tCase.requestBodyLimitAction

		t.Run(tName, func(t *testing.T) {
			for wName, writer := range requestBodyWriters {
				t.Run(wName, func(t *testing.T) {
					tx := waf.NewTransaction()
					_, err := tx.requestBodyBuffer.Write([]byte("ab"))
					if err != nil {
						t.Fatalf("unexpected error when writing to body buffer directly: %s", err.Error())
					}
					tx.interruption = tCase.preexistingInterruption

					it, n, err := writer(tx, "c")
					if err != nil {
						t.Fatalf("unexpected error: %s", err.Error())
					}

					if it != tCase.preexistingInterruption {
						t.Fatalf("unexpected interruption")
					}

					if n != 0 {
						t.Fatalf("unexpected number of bytes written")
					}

					if err := tx.Close(); err != nil {
						t.Fatalf("Failed to close transaction: %s", err.Error())
					}
				})
			}
		})
	}
}

func TestWriteRequestBodyIsNopWhenBodyIsNotAccesible(t *testing.T) {
	testCases := []struct {
		ruleEngine        types.RuleEngineStatus
		requestBodyAccess bool
	}{
		{
			ruleEngine: types.RuleEngineOff,
		},
		{
			ruleEngine:        types.RuleEngineOn,
			requestBodyAccess: false,
		},
	}

	for _, tCase := range testCases {
		t.Run(fmt.Sprintf(
			"ruleEngine = %s and requestBodyAccess = %t",
			tCase.ruleEngine.String(),
			tCase.requestBodyAccess,
		), func(t *testing.T) {
			waf := NewWAF()
			waf.RuleEngine = tCase.ruleEngine
			waf.RequestBodyAccess = tCase.requestBodyAccess

			for wName, writer := range requestBodyWriters {
				t.Run(wName, func(t *testing.T) {
					tx := waf.NewTransaction()
					it, n, err := writer(tx, "abc")
					if err != nil {
						t.Fatalf("unexpected error: %s", err.Error())
					}

					if it != nil {
						t.Fatalf("unexpected interruption")
					}

					if n != 0 {
						t.Fatalf("unexpected number of bytes written")
					}

					if err := tx.Close(); err != nil {
						t.Fatalf("Failed to close transaction: %s", err.Error())
					}
				})
			}
		})
	}
}

func TestResponseHeader(t *testing.T) {
	tx := makeTransaction(t)
	tx.AddResponseHeader("content-type", "test")
	if tx.variables.responseContentType.Get() != "test" {
		t.Fatal("invalid RESPONSE_CONTENT_TYPE after response headers")
	}

	interruption := tx.ProcessResponseHeaders(200, "OK")
	if interruption != nil {
		t.Fatal("unexpected interruption")
	}
}

func TestProcessRequestHeadersDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff

	if !tx.IsRuleEngineOff() {
		t.Fatal("expected Engine off")
	}

	_ = tx.ProcessRequestHeaders()
	if tx.lastPhase != 0 { // 0 means no phases have been evaluated
		t.Fatal("unexpected rule evaluation")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestProcessRequestBodyDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal("failed to process request body")
	}
	if tx.lastPhase != 0 {
		t.Fatal("unexpected rule evaluation")
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestProcessResponseHeadersDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff
	_ = tx.ProcessResponseHeaders(200, "OK")
	if tx.lastPhase != 0 {
		t.Fatal("unexpected rule evaluation")
	}
}

func TestProcessResponseBodyDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Fatal("Failed to process response body")
	}
	if tx.lastPhase != 0 {
		t.Fatal("unexpected rule evaluation")
	}
}

func TestProcessLoggingDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff
	tx.ProcessLogging()
	if tx.lastPhase != 0 {
		t.Fatal("unexpected rule evaluation")
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestAuditLog(t *testing.T) {
	tx := makeTransaction(t)
	tx.AuditLogParts = types.AuditLogParts("ABCDEFGHIJK")
	al := tx.AuditLog()
	if al.Transaction().ID() != tx.id {
		t.Fatal("invalid auditlog id")
	}
	// TODO more checks
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

var responseBodyWriters = map[string]func(tx *Transaction, body string) (*types.Interruption, int, error){
	"WriteResponsequestBody": func(tx *Transaction, body string) (*types.Interruption, int, error) {
		return tx.WriteResponseBody([]byte(body))
	},
	"ReadResponseBodyFromKnownLen": func(tx *Transaction, body string) (*types.Interruption, int, error) {
		return tx.ReadResponseBodyFrom(strings.NewReader(body))
	},
	"ReadResponseBodyFromUnknownLen": func(tx *Transaction, body string) (*types.Interruption, int, error) {
		return tx.ReadResponseBodyFrom(struct{ io.Reader }{
			strings.NewReader(body),
		})
	},
}

func TestWriteResponseBody(t *testing.T) {
	const (
		urlencodedBody    = "some=result&second=data"
		urlencodedBodyLen = len(urlencodedBody)
	)

	testCases := []struct {
		name                    string
		responseBodyLimit       int
		responseBodyLimitAction types.BodyLimitAction
		shouldInterrupt         bool
		limitReached            bool // If the limit is reached, OUTBOUND_DATA_ERROR should be set
	}{
		{
			name:                    "LimitNotReached",
			responseBodyLimit:       urlencodedBodyLen + 2,
			responseBodyLimitAction: types.BodyLimitAction(-1),
			limitReached:            false,
		},
		{
			name:                    "LimitReachedAndRejects",
			responseBodyLimit:       urlencodedBodyLen - 3,
			responseBodyLimitAction: types.BodyLimitActionReject,
			shouldInterrupt:         true,
			limitReached:            true,
		},
		{
			name:                    "LimitReachedAndPartialProcessing",
			responseBodyLimit:       urlencodedBodyLen - 3,
			responseBodyLimitAction: types.BodyLimitActionProcessPartial,
			limitReached:            true,
		},
		{
			name:              "LimitReachedAndPartialProcessingDefaultValue",
			responseBodyLimit: urlencodedBodyLen - 3,
			// Omitting requestBodyLimitAction defaults to ProcessPartial
			// responseBodyLimitAction: types.BodyLimitActionProcessPartial,
			limitReached: true,
		},
	}

	urlencodedBodyLenThird := urlencodedBodyLen / 3
	bodyChunks := map[string][]string{
		"BodyInOneShot":     {urlencodedBody},
		"BodyInThreeChunks": {urlencodedBody[0:urlencodedBodyLenThird], urlencodedBody[urlencodedBodyLenThird : 2*urlencodedBodyLenThird], urlencodedBody[2*urlencodedBodyLenThird:]},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			for name, writeResponseBody := range responseBodyWriters {
				t.Run(name, func(t *testing.T) {
					for name, chunks := range bodyChunks {
						t.Run(name, func(t *testing.T) {
							waf := NewWAF()
							waf.RuleEngine = types.RuleEngineOn
							waf.ResponseBodyMimeTypes = []string{"text/plain"}
							waf.ResponseBodyAccess = true
							waf.ResponseBodyLimit = int64(testCase.responseBodyLimit)
							waf.ResponseBodyLimitAction = testCase.responseBodyLimitAction

							if err := waf.Validate(); err != nil {
								t.Fatalf("failed to validate the WAF: %s", err.Error())
							}

							tx := waf.NewTransaction()
							tx.AddResponseHeader("content-type", "text/plain")

							it := tx.ProcessResponseHeaders(200, "HTTP/1")
							if it != nil {
								t.Fatal("Unexpected interruption on headers")
							}

							var err error

							for _, c := range chunks {
								if it, _, err = writeResponseBody(tx, c); err != nil {
									t.Fatalf("Failed to write body buffer: %s", err.Error())
								}
							}
							if testCase.limitReached && tx.variables.outboundDataError.Get() != "1" {
								t.Fatalf("Expected OUTBOUND_DATA_ERROR to be set")
							}
							if testCase.shouldInterrupt {
								if it == nil {
									t.Fatal("Expected interruption, got nil")
								}
							} else {
								it, err := tx.ProcessResponseBody()
								if err != nil {
									t.Fatal(err)
								}

								if it != nil {
									t.Fatalf("Unexpected interruption")
								}
								// checking if the body has been populated up to the first POST arg
								index := strings.Index(urlencodedBody, "&")
								if tx.variables.responseBody.Get()[:index] != urlencodedBody[:index] {
									t.Fatal("failed to set response body")
								}
							}

							if err := tx.Close(); err != nil {
								t.Fatalf("Failed to close transaction: %s", err.Error())
							}
						})
					}

				})
			}

		})
	}
}

func TestWriteResponseBodyOnLimitReached(t *testing.T) {
	testCases := map[string]struct {
		responseBodyLimitAction types.BodyLimitAction
		preexistingInterruption *types.Interruption
	}{
		"reject": {
			responseBodyLimitAction: types.BodyLimitActionReject,
			preexistingInterruption: &types.Interruption{
				RuleID: 123,
			},
		},
		"partial processing": {
			responseBodyLimitAction: types.BodyLimitActionProcessPartial,
		},
	}

	for tName, tCase := range testCases {
		waf := NewWAF()
		waf.RuleEngine = types.RuleEngineOn
		waf.ResponseBodyAccess = true
		waf.ResponseBodyLimit = 2
		waf.ResponseBodyLimitAction = tCase.responseBodyLimitAction

		t.Run(tName, func(t *testing.T) {
			for wName, writer := range responseBodyWriters {
				t.Run(wName, func(t *testing.T) {
					tx := waf.NewTransaction()
					_, err := tx.responseBodyBuffer.Write([]byte("ab"))
					if err != nil {
						t.Fatalf("unexpected error when writing to body buffer directly: %s", err.Error())
					}
					tx.interruption = tCase.preexistingInterruption

					it, n, err := writer(tx, "c")
					if err != nil {
						t.Fatalf("unexpected error: %s", err.Error())
					}

					if it != tCase.preexistingInterruption {
						t.Fatalf("unexpected interruption")
					}

					if n != 0 {
						t.Fatalf("unexpected number of bytes written")
					}

					if err := tx.Close(); err != nil {
						t.Fatalf("Failed to close transaction: %s", err.Error())
					}
				})
			}
		})
	}
}

func TestWriteResponseBodyIsNopWhenBodyIsNotAccesible(t *testing.T) {
	testCases := []struct {
		ruleEngine         types.RuleEngineStatus
		responseBodyAccess bool
	}{
		{
			ruleEngine: types.RuleEngineOff,
		},
		{
			ruleEngine:         types.RuleEngineOn,
			responseBodyAccess: false,
		},
	}

	for _, tCase := range testCases {
		t.Run(fmt.Sprintf(
			"ruleEngine = %s and responseBodyAccess = %t",
			tCase.ruleEngine.String(),
			tCase.responseBodyAccess,
		), func(t *testing.T) {
			waf := NewWAF()
			waf.RuleEngine = tCase.ruleEngine
			waf.ResponseBodyAccess = tCase.responseBodyAccess

			for wName, writer := range responseBodyWriters {
				t.Run(wName, func(t *testing.T) {
					tx := waf.NewTransaction()
					it, n, err := writer(tx, "abc")
					if err != nil {
						t.Fatalf("unexpected error: %s", err.Error())
					}

					if it != nil {
						t.Fatalf("unexpected interruption")
					}

					if n != 0 {
						t.Fatalf("unexpected number of bytes written")
					}

					if err := tx.Close(); err != nil {
						t.Fatalf("Failed to close transaction: %s", err.Error())
					}
				})
			}
		})
	}
}

func TestAuditLogFields(t *testing.T) {
	tx := makeTransaction(t)
	tx.AuditLogParts = types.AuditLogParts("ABCDEFGHIJK")
	tx.AddRequestHeader("test", "test")
	tx.AddResponseHeader("test", "test")
	rule := NewRule()
	rule.ID_ = 131
	rule.Log = true
	tx.MatchRule(rule, []types.MatchData{
		&corazarules.MatchData{
			Variable_: variables.UniqueID,
		},
	})
	if len(tx.matchedRules) == 0 || tx.matchedRules[0].Rule().ID() != rule.ID_ {
		t.Fatal("failed to match rule for audit")
	}
	al := tx.AuditLog()
	if len(al.Messages()) == 0 || al.Messages()[0].Data().ID() != rule.ID_ {
		t.Fatal("failed to add rules to audit logs")
	}

	if len(al.Transaction().Request().Headers()) == 0 || al.Transaction().Request().Headers()["test"][0] != "test" {
		t.Fatal("failed to add request header to audit log")
	}
	if len(al.Transaction().Response().Headers()) == 0 || al.Transaction().Response().Headers()["test"][0] != "test" {
		t.Fatal("failed to add Response header to audit log")
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestResetCapture(t *testing.T) {
	tx := makeTransaction(t)
	tx.Capture = true
	tx.CaptureField(5, "test")
	if tx.variables.tx.Get("5")[0] != "test" {
		t.Fatal("failed to set capture field from tx")
	}
	tx.resetCaptures()
	if tx.variables.tx.Get("5")[0] != "" {
		t.Fatal("failed to reset capture field from tx")
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestRelevantAuditLogging(t *testing.T) {
	tests := []struct {
		name         string
		status       string
		interruption *types.Interruption
		relevantLog  bool
	}{
		{
			name:         "TestRelevantAuditLogging",
			status:       "403",
			interruption: nil,
			relevantLog:  true,
		},
		{
			name:         "TestNotRelevantAuditLogging",
			status:       "200",
			interruption: nil,
			relevantLog:  false,
		},
		{
			name: "TestRelevantAuditLoggingWithInterruption",
			interruption: &types.Interruption{
				Status: 403,
				Action: "deny",
			},
			relevantLog: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := makeTransaction(t)
			debugLog := bytes.Buffer{}
			tx.debugLogger = debuglog.Default().WithLevel(debuglog.LevelDebug).WithOutput(&debugLog)
			tx.WAF.AuditLogRelevantStatus = regexp.MustCompile(`(403)`)
			tx.variables.responseStatus.Set(tt.status)
			tx.interruption = tt.interruption
			tx.AuditEngine = types.AuditEngineRelevantOnly
			tx.audit = true // Mimics that there is something to audit
			tx.ProcessLogging()
			// TODO how do we check if the log was written?
			if err := tx.Close(); err != nil {
				t.Error(err)
			}
			if tt.relevantLog && strings.Contains(debugLog.String(), "Transaction status not marked for audit logging") {
				t.Errorf("unexpected debug log: %q. Transaction status should be marked for audit logging", debugLog.String())
			}
			if !tt.relevantLog && !strings.Contains(debugLog.String(), "Transaction status not marked for audit logging") {
				t.Errorf("missing debug log. Transaction status should be not marked for audit logging not being relevant")
			}
		})
	}
}

func TestLogCallback(t *testing.T) {

	testCases := []struct {
		name            string
		engineStatus    types.RuleEngineStatus
		action          plugintypes.Action
		shouldInterrupt bool
		expectedLogLine string
	}{
		{
			name:            "disruptive action",
			engineStatus:    types.RuleEngineOn,
			action:          &dummyDenyAction{},
			shouldInterrupt: true,
			expectedLogLine: "Coraza: Access denied",
		},
		{
			name:            "disruptive action detection only",
			engineStatus:    types.RuleEngineDetectionOnly,
			action:          &dummyDenyAction{},
			shouldInterrupt: false,
			expectedLogLine: "Coraza: Warning",
		},
		{
			name:            "no disruptive action",
			engineStatus:    types.RuleEngineOn,
			action:          &dummyNonDisruptiveAction{},
			shouldInterrupt: false,
			expectedLogLine: "Coraza: Warning",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			waf := NewWAF()
			buffer := ""
			waf.SetErrorCallback(func(mr types.MatchedRule) {
				buffer = mr.ErrorLog()
			})
			waf.RuleEngine = testCase.engineStatus
			tx := waf.NewTransaction()
			rule := NewRule()
			rule.ID_ = 1
			rule.LogID_ = "1"
			rule.Phase_ = 1
			rule.Log = true
			_ = rule.AddAction("deny", testCase.action)
			tx.MatchRule(rule, []types.MatchData{
				&corazarules.MatchData{
					Variable_: variables.UniqueID,
				},
			})
			tx.WAF.Rules.rules = append(tx.WAF.Rules.rules, *rule)

			it := tx.ProcessRequestHeaders()
			if testCase.shouldInterrupt {
				if it == nil {
					t.Fatal("Expected interruption on headers with disruptive action")
				}
			} else {
				if it != nil {
					t.Fatal("Unexpected interruption on headers without disruptive action")
				}
			}

			if buffer == "" || !strings.Contains(buffer, tx.id) {
				t.Fatal("failed to call error log callback")
			}
			if !strings.Contains(buffer, testCase.expectedLogLine) {
				t.Fatalf("Expected string \"%s\" with disruptive rule, got %s", testCase.expectedLogLine, buffer)

				if err := tx.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestHeaderSetters(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.AddRequestHeader("cookie", "abc=def;hij=klm")
	tx.AddRequestHeader("test1", "test2")
	c := tx.variables.requestCookies.Get("abc")[0]
	if c != "def" {
		t.Fatalf("failed to set cookie, got %q", c)
	}
	if tx.variables.requestHeaders.Get("cookie")[0] != "abc=def;hij=klm" {
		t.Fatal("failed to set request header")
	}
	if !utils.InSlice("cookie", collectionValues(t, tx.variables.requestHeadersNames)) {
		t.Fatal("failed to set header name", collectionValues(t, tx.variables.requestHeadersNames))
	}
	if !utils.InSlice("abc", collectionValues(t, tx.variables.requestCookiesNames)) {
		t.Fatal("failed to set cookie name")
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestCookiesNotUrldecoded(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	fullCookie := "abc=%7Bd+e+f%7D;hij=%7Bklm%7D"
	expectedUrlencodedAbcCookieValue := "%7Bd+e+f%7D"
	unexpectedUrldencodedAbcCookieValue := "{d e f}"
	tx.AddRequestHeader("cookie", fullCookie)
	c := tx.variables.requestCookies.Get("abc")[0]
	if c != expectedUrlencodedAbcCookieValue {
		if c == unexpectedUrldencodedAbcCookieValue {
			t.Errorf("failed to set cookie, unexpected urldecoding. Got: %q, expected: %q", unexpectedUrldencodedAbcCookieValue, expectedUrlencodedAbcCookieValue)
		} else {
			t.Errorf("failed to set cookie, got %q", c)
		}
	}
	if tx.variables.requestHeaders.Get("cookie")[0] != fullCookie {
		t.Errorf("failed to set request header, got: %q, expected: %q", tx.variables.requestHeaders.Get("cookie")[0], fullCookie)
	}
	if !utils.InSlice("cookie", collectionValues(t, tx.variables.requestHeadersNames)) {
		t.Error("failed to set header name", collectionValues(t, tx.variables.requestHeadersNames))
	}
	if !utils.InSlice("abc", collectionValues(t, tx.variables.requestCookiesNames)) {
		t.Error("failed to set cookie name")
	}
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func TestMultipleCookiesWithSpaceBetweenThem(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	multipleCookies := "cookie1=value1; cookie2=value2;    cookie1=value2"
	tx.AddRequestHeader("cookie", multipleCookies)
	v11 := tx.variables.requestCookies.Get("cookie1")[0]
	if v11 != "value1" {
		t.Errorf("failed to set cookie, got %q", v11)
	}
	v12 := tx.variables.requestCookies.Get("cookie1")[1]
	if v12 != "value2" {
		t.Errorf("failed to set cookie, got %q", v12)
	}
	v2 := tx.variables.requestCookies.Get("cookie2")[0]
	if v2 != "value2" {
		t.Errorf("failed to set cookie, got %q", v2)
	}
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func collectionValues(t *testing.T, col collection.Collection) []string {
	t.Helper()
	var values []string
	for _, v := range col.FindAll() {
		values = append(values, v.Value())
	}
	return values
}

func TestRequestBodyProcessingAlgorithm(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.RuleEngine = types.RuleEngineOn
	tx.RequestBodyAccess = true
	tx.ForceRequestBodyVariable = true
	tx.AddRequestHeader("content-type", "text/plain")
	tx.AddRequestHeader("content-length", "7")
	tx.ProcessRequestHeaders()
	if _, err := tx.requestBodyBuffer.Write([]byte("test123")); err != nil {
		t.Fatal("Failed to write request body buffer")
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal("failed to process request body")
	}
	if tx.variables.requestBody.Get() != "test123" {
		t.Fatal("failed to set request body")
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestProcessBodiesSkippedIfHeadersPhasesNotReached(t *testing.T) {
	logBuffer := &bytes.Buffer{}
	waf := NewWAF()
	waf.SetDebugLogOutput(logBuffer)
	_ = waf.SetDebugLogLevel(debuglog.LevelDebug)
	tx := waf.NewTransaction()
	tx.RuleEngine = types.RuleEngineOn
	tx.RequestBodyAccess = true
	// Current phase is PhaseUnknown (ProcessRequestHeaders has not been called)
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Fatal(err)
	}
	if it != nil {
		t.Fatal("Unexpected interruption")
	}
	it, err = tx.ProcessResponseBody()
	if err != nil {
		t.Fatal(err)
	}
	if it != nil {
		t.Fatal("Unexpected interruption")
	}
	logEntries := strings.Split(strings.TrimSpace(logBuffer.String()), "\n")
	// At this point we are expecting three log entries:
	// [0] New transaction log
	// [1] Anomalous call before request headers evaluation
	// [2] Anomalous call before response headers evaluation
	if want, have := 3, len(logEntries); want != have {
		t.Fatalf("unexpected number of log entries, want %d, have %d", want, have)
	}
	if want, have := "has been called before request headers evaluation", logEntries[1]; !strings.Contains(have, want) {
		t.Fatalf("unexpected message, want %q, have %q", want, have)
	}
	if want, have := "has been called before response headers evaluation", logEntries[2]; !strings.Contains(have, want) {
		t.Fatalf("unexpected message, want %q, have %q", want, have)
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxVariables(t *testing.T) {
	tx := makeTransaction(t)
	rv := ruleVariableParams{
		Variable: variables.RequestHeaders,
		KeyStr:   "ho.*",
		KeyRx:    regexp.MustCompile("ho.*"),
	}
	if len(tx.GetField(rv)) != 1 || tx.GetField(rv)[0].Value() != "www.test.com:80" {
		t.Fatalf("failed to match rule variable REQUEST_HEADERS:host, %d matches, %v", len(tx.GetField(rv)), tx.GetField(rv))
	}
	rv.Count = true
	if len(tx.GetField(rv)) == 0 || tx.GetField(rv)[0].Value() != "1" {
		t.Fatalf("failed to get count for regexp variable")
	}
	// now nil key
	rv.KeyRx = nil
	if len(tx.GetField(rv)) == 0 {
		t.Fatal("failed to match rule variable REQUEST_HEADERS with nil key")
	}
	rv.KeyStr = ""
	f := tx.GetField(rv)
	if len(f) == 0 {
		t.Fatal("failed to count variable REQUEST_HEADERS ")
	}
	count, err := strconv.Atoi(f[0].Value())
	if err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("failed to match rule variable REQUEST_HEADERS with count, %v", rv)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTxVariablesExceptions(t *testing.T) {
	tx := makeTransaction(t)
	rv := ruleVariableParams{
		Variable: variables.RequestHeaders,
		KeyStr:   "ho.*",
		KeyRx:    regexp.MustCompile("ho.*"),
		Exceptions: []ruleVariableException{
			{KeyStr: "host"},
		},
	}
	fields := tx.GetField(rv)
	if len(fields) != 0 {
		t.Fatalf("REQUEST_HEADERS:host should not match, got %d matches, %v", len(fields), fields)
	}
	rv.Exceptions = nil
	fields = tx.GetField(rv)
	if len(fields) != 1 || fields[0].Value() != "www.test.com:80" {
		t.Fatalf("failed to match rule variable REQUEST_HEADERS:host, %d matches, %v", len(fields), fields)
	}
	rv.Exceptions = []ruleVariableException{
		{
			KeyRx: regexp.MustCompile("ho.*"),
		},
	}
	fields = tx.GetField(rv)
	if len(fields) != 0 {
		t.Fatalf("REQUEST_HEADERS:host should not match, got %d matches, %v", len(fields), fields)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTransactionSyncPool(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.matchedRules = append(tx.matchedRules, &corazarules.MatchedRule{
		Rule_: &corazarules.RuleMetadata{
			ID_: 1234,
		},
	})
	for i := 0; i < 1000; i++ {
		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}
		tx = waf.NewTransaction()
		if len(tx.matchedRules) != 0 {
			t.Fatalf("failed to sync transaction pool, %d rules found after %d attempts", len(tx.matchedRules), i+1)
			return
		}
	}
}

func TestTxPhase4Magic(t *testing.T) {
	waf := NewWAF()
	waf.ResponseBodyAccess = true
	waf.ResponseBodyLimit = 3
	waf.ResponseBodyLimitAction = types.BodyLimitActionProcessPartial
	waf.ResponseBodyMimeTypes = []string{"text/html"}
	tx := waf.NewTransaction()
	tx.AddResponseHeader("content-type", "text/html")
	tx.ProcessRequestHeaders()
	_, _ = tx.ProcessRequestBody()
	tx.ProcessResponseHeaders(200, "HTTP/1.1")
	if it, _, err := tx.WriteResponseBody([]byte("more bytes")); it != nil || err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Fatal(err)
	}
	if tx.variables.outboundDataError.Get() != "1" {
		t.Fatal("failed to set outbound data error")
	}
	if tx.variables.responseBody.Get() != "mor" {
		t.Fatal("failed to set response body")
	}
}

func TestVariablesMatch(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.matchVariable(&corazarules.MatchData{
		Variable_: variables.ArgsNames,
		Key_:      "sample",
		Value_:    "samplevalue",
	})
	expect := map[variables.RuleVariable]string{
		variables.MatchedVar:     "samplevalue",
		variables.MatchedVarName: "ARGS_NAMES:sample",
	}

	for k, v := range expect {
		if m := (tx.Collection(k)).(*collections.Single).Get(); m != v {
			t.Fatalf("failed to match variable %s, Expected: %s, got: %s", k.Name(), v, m)
		}
	}

	if len(tx.variables.matchedVars.Get("ARGS_NAMES:sample")) == 0 {
		t.Fatalf("failed to match variable %s, got 0", variables.MatchedVars.Name())
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxReqBodyForce(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.ProcessRequestHeaders()
	tx.RequestBodyAccess = true
	tx.ForceRequestBodyVariable = true
	if _, err := tx.requestBodyBuffer.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	if tx.variables.requestBody.Get() != "test" {
		t.Fatal("failed to set request body")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxReqBodyForceNegative(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.RequestBodyAccess = true
	tx.ForceRequestBodyVariable = false
	if _, err := tx.requestBodyBuffer.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	if tx.variables.requestBody.Get() == "test" {
		t.Fatal("reqbody should not be there")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxProcessConnection(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.ProcessConnection("127.0.0.1", 80, "127.0.0.2", 8080)
	if tx.variables.remoteAddr.Get() != "127.0.0.1" {
		t.Fatal("failed to set client ip")
	}
	if rp, _ := strconv.Atoi(tx.variables.remotePort.Get()); rp != 80 {
		t.Fatal("failed to set client port")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxSetServerName(t *testing.T) {
	logBuffer := &bytes.Buffer{}

	waf := NewWAF()
	waf.SetDebugLogOutput(logBuffer)
	_ = waf.SetDebugLogLevel(debuglog.LevelWarn)

	tx := waf.NewTransaction()
	tx.lastPhase = types.PhaseRequestHeaders
	tx.SetServerName("coraza.io")
	if tx.variables.serverName.Get() != "coraza.io" {
		t.Fatal("failed to set server name")
	}
	logEntries := strings.Split(strings.TrimSpace(logBuffer.String()), "\n")
	if want, have := 1, len(logEntries); want != have {
		t.Fatalf("unexpected number of log entries, want %d, have %d", want, have)
	}

	if want, have := "SetServerName has been called after ProcessRequestHeaders", logEntries[0]; !strings.Contains(have, want) {
		t.Fatalf("unexpected message, want %q, have %q", want, have)
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxAddArgument(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.ProcessConnection("127.0.0.1", 80, "127.0.0.2", 8080)
	tx.AddGetRequestArgument("test", "testvalue")
	if tx.variables.argsGet.Get("test")[0] != "testvalue" {
		t.Fatal("failed to set args get")
	}
	tx.AddPostRequestArgument("ptest", "ptestvalue")
	if tx.variables.argsPost.Get("ptest")[0] != "ptestvalue" {
		t.Fatal("failed to set args post")
	}
	tx.AddPathRequestArgument("ptest2", "ptestvalue")
	if tx.variables.argsPath.Get("ptest2")[0] != "ptestvalue" {
		t.Fatal("failed to set args post")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxGetField(t *testing.T) {
	tx := makeTransaction(t)
	rvp := ruleVariableParams{
		Variable: variables.Args,
	}
	if f := tx.GetField(rvp); len(f) != 3 {
		t.Fatalf("failed to get field, expected 2, got %d", len(f))
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxProcessURI(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	uri := "http://example.com/path/to/file.html?query=string&other=value"
	tx.ProcessURI(uri, "GET", "HTTP/1.1")
	if s := tx.variables.requestURI.Get(); s != uri {
		t.Fatalf("failed to set request uri, got %s", s)
	}
	if s := tx.variables.requestBasename.Get(); s != "file.html" {
		t.Fatalf("failed to set request path, got %s", s)
	}
	if tx.variables.queryString.Get() != "query=string&other=value" {
		t.Fatal("failed to set request query")
	}
	if v := tx.variables.args.FindAll(); len(v) != 2 {
		t.Fatalf("failed to set request args, got %d", len(v))
	}
	if v := tx.variables.args.FindString("other"); v[0].Value() != "value" {
		t.Fatalf("failed to set request args, got %v", v)
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func BenchmarkTransactionCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		makeTransaction(b)
	}
}

func makeTransaction(t testing.TB) *Transaction {
	t.Helper()
	tx := NewWAF().NewTransaction()
	tx.RequestBodyAccess = true
	ht := []string{
		"POST /testurl.php?id=123&b=456 HTTP/1.1",
		"Host: www.test.com:80",
		"Cookie: test=123",
		"Content-Type: application/x-www-form-urlencoded",
		"X-Test-Header: test456",
		"Content-Length: 13",
		"",
		"testfield=456",
	}
	data := strings.Join(ht, "\r\n")
	_, err := tx.ParseRequestReader(strings.NewReader(data))
	if err != nil {
		panic(err)
	}
	return tx
}

func makeTransactionMultipart(t *testing.T) *Transaction {
	if t != nil {
		t.Helper()
	}
	tx := NewWAF().NewTransaction()
	tx.RequestBodyAccess = true
	ht := []string{
		"POST /testurl.php?id=123&b=456 HTTP/1.1",
		"Host: www.test.com:80",
		"Cookie: test=123",
		"Content-Type: multipart/form-data; boundary=---------------------------9051914041544843365972754266",
		"X-Test-Header: test456",
		"Content-Length: 545",
		"",
		`-----------------------------9051914041544843365972754266`,
		`Content-Disposition: form-data; name="testfield"`,
		``,
		`456`,
		`-----------------------------9051914041544843365972754266`,
		`Content-Disposition: form-data; name="file1"; filename="a.txt"`,
		`Content-Type: text/plain`,
		``,
		`Content of a.txt.`,
		``,
		`-----------------------------9051914041544843365972754266`,
		`Content-Disposition: form-data; name="file2"; filename="a.html"`,
		`Content-Type: text/html`,
		``,
		`<!DOCTYPE html><title>Content of a.html.</title>`,
		``,
		`-----------------------------9051914041544843365972754266--`,
	}
	data := strings.Join(ht, "\r\n")
	_, err := tx.ParseRequestReader(strings.NewReader(data))
	if err != nil {
		panic(err)
	}
	return tx
}

func validateMacroExpansion(tests map[string]string, tx *Transaction, t *testing.T) {
	for k, v := range tests {
		m, err := macro.NewMacro(k)
		if err != nil {
			t.Fatal(err)
		}
		res := m.Expand(tx)
		if res != v {
			if testing.Verbose() {
				fmt.Println(tx)
				fmt.Println("===STACK===\n", string(debug.Stack())+"\n===STACK===")
			}
			t.Fatal("Failed set transaction for " + k + ", expected " + v + ", got " + res)
		}
	}
}

func TestMacro(t *testing.T) {
	tx := makeTransaction(t)
	tx.variables.tx.Set("some", []string{"secretly"})
	m, err := macro.NewMacro("%{unique_id}")
	if err != nil {
		t.Fatal(err)
	}
	if m.Expand(tx) != tx.id {
		t.Fatalf("%s != %s", m.Expand(tx), tx.id)
	}
	m, err = macro.NewMacro("some complex text %{tx.some} wrapped in m")
	if err != nil {
		t.Fatal(err)
	}
	if m.Expand(tx) != "some complex text secretly wrapped in m" {
		t.Fatalf("failed to expand m, got %s\n%v", m.Expand(tx), m)
	}

	_, err = macro.NewMacro("some complex text %{tx.some} wrapped in m %{tx.some}")
	if err != nil {
		t.Fatal(err)
		return
	}
	// TODO(anuraaga): Decouple this test from transaction implementation.
	// if !macro.IsExpandable() || len(macro.tokens) != 4 || macro.Expand(tx) != "some complex text secretly wrapped in m secretly" {
	//   t.Fatalf("failed to parse replacements %v", macro.tokens)
	// }

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func BenchmarkMacro(b *testing.B) {
	tests := []string{
		"%{tx.a}",
		"%{tx.a} %{tx.b}",
		"goodbye world",
	}

	tx := makeTransaction(b)
	tx.variables.tx.Set("a", []string{"hello"})
	tx.variables.tx.Set("b", []string{"world"})

	for _, tc := range tests {
		m, err := macro.NewMacro(tc)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(tc, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				m.Expand(tx)
			}
		})
	}
}

func TestProcessorsIdempotencyWithAlreadyRaisedInterruption(t *testing.T) {
	logBuffer := &bytes.Buffer{}

	waf := NewWAF()
	waf.SetDebugLogOutput(logBuffer)
	_ = waf.SetDebugLogLevel(debuglog.LevelError)

	expectedInterruption := &types.Interruption{
		RuleID: 123,
	}

	tx := waf.NewTransaction()
	tx.interruption = expectedInterruption

	testCases := map[string]func(tx *Transaction) *types.Interruption{
		"ProcessRequestHeaders": func(tx *Transaction) *types.Interruption {
			return tx.ProcessRequestHeaders()
		},
		"ProcessRequestBody": func(tx *Transaction) *types.Interruption {
			it, err := tx.ProcessRequestBody()
			if err != nil {
				t.Fatal("unexpected error when processing request body")
			}
			return it
		},
		"ProcessResponseHeaders": func(tx *Transaction) *types.Interruption {
			return tx.ProcessResponseHeaders(200, "HTTP/1")
		},
		"ProcessResponseBody": func(tx *Transaction) *types.Interruption {
			it, err := tx.ProcessResponseBody()
			if err != nil {
				t.Fatal("unexpected error when processing response body")
			}
			return it
		},
	}

	for processor, tCase := range testCases {
		t.Run(processor, func(t *testing.T) {
			logBuffer.Reset()

			it := tCase(tx)
			if it == nil {
				t.Fatal("expected interruption")
			}

			if it != expectedInterruption {
				t.Fatal("unexpected interruption")
			}

			logEntries := strings.Split(strings.TrimSpace(logBuffer.String()), "\n")
			if want, have := 1, len(logEntries); want != have {
				t.Fatalf("unexpected number of log entries, want %d, have %d", want, have)
			}

			expectedMessage := fmt.Sprintf("Calling %s but there is a preexisting interruption", processor)

			if want, have := expectedMessage, logEntries[0]; !strings.Contains(have, want) {
				t.Fatalf("unexpected message, want to contain %q in %q", want, have)
			}
		})
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestIterationStops(t *testing.T) {
	// This is a valid test of iteration mechanics but is really overkill. We mostly do it for
	// code coverage.

	waf := NewWAF()
	tx := waf.NewTransaction()

	// Order doesn't matter, iterate once without stopping to know the order
	var allVars []variables.RuleVariable
	tx.Variables().All(func(v variables.RuleVariable, _ collection.Collection) bool {
		allVars = append(allVars, v)
		return true
	})

	for i, stopV := range allVars {
		t.Run(stopV.Name(), func(t *testing.T) {
			var haveVars []variables.RuleVariable
			tx.Variables().All(func(v variables.RuleVariable, _ collection.Collection) bool {
				haveVars = append(haveVars, v)
				return v != stopV
			})

			if want, have := i+1, len(haveVars); want != have {
				t.Fatalf("stopped with unexpected number of variables, want %d, have %d", want, have)
			}

			for j, v := range haveVars {
				if want, have := allVars[j], v; want != have {
					t.Fatalf("unexpected variable at index %d, want %s, have %s", j, want.Name(), have.Name())
				}
			}
		})
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestTxAddResponseArgs(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.AddResponseArgument("samplekey", "samplevalue")
	if tx.variables.responseArgs.Get("samplekey")[0] != "samplevalue" {
		t.Fatalf("failed to add response argument")
	}
}

func TestAddGetArgsWithOverlimit(t *testing.T) {
	testCases := []int{1, 2, 5, 1000}

	for _, limit := range testCases {
		waf := NewWAF()
		tx := waf.NewTransaction()
		tx.WAF.ArgumentLimit = limit
		for i := 0; i < limit+1; i++ {
			tx.AddGetRequestArgument(fmt.Sprintf("testKey%d", i), "samplevalue")
		}
		if tx.variables.argsGet.Len() > waf.ArgumentLimit {
			t.Fatal("Argument limit is failed while add get args")
		}

		if err := tx.Close(); err != nil {
			t.Fatalf("Failed to close transaction: %s", err.Error())
		}
	}
}

func TestAddPostArgsWithOverlimit(t *testing.T) {
	testCases := []int{1, 2, 5, 1000}

	for _, limit := range testCases {
		waf := NewWAF()
		tx := waf.NewTransaction()
		tx.WAF.ArgumentLimit = limit
		for i := 0; i < limit+1; i++ {
			tx.AddPostRequestArgument(fmt.Sprintf("testKey%d", i), "samplevalue")
		}
		if tx.variables.argsPost.Len() > waf.ArgumentLimit {
			t.Fatal("Argument limit is failed while add post args")
		}

		if err := tx.Close(); err != nil {
			t.Fatalf("Failed to close transaction: %s", err.Error())
		}
	}
}

func TestAddPathArgsWithOverlimit(t *testing.T) {
	testCases := []int{1, 2, 5, 1000}

	for _, limit := range testCases {
		waf := NewWAF()
		tx := waf.NewTransaction()
		tx.WAF.ArgumentLimit = limit
		for i := 0; i < limit+1; i++ {
			tx.AddPathRequestArgument(fmt.Sprintf("testKey%d", i), "samplevalue")
		}
		if tx.variables.argsPath.Len() > waf.ArgumentLimit {
			t.Fatal("Argument limit is failed while add path args")
		}

		if err := tx.Close(); err != nil {
			t.Fatalf("Failed to close transaction: %s", err.Error())
		}
	}
}

func TestAddResponseArgsWithOverlimit(t *testing.T) {
	testCases := []int{1, 2, 5, 1000}

	for _, limit := range testCases {
		waf := NewWAF()
		tx := waf.NewTransaction()
		tx.WAF.ArgumentLimit = limit
		for i := 0; i < limit+1; i++ {
			tx.AddResponseArgument(fmt.Sprintf("testKey%d", i), "samplevalue")
		}
		if tx.variables.responseArgs.Len() > waf.ArgumentLimit {
			t.Fatal("Argument limit is failed while add response args")
		}

		if err := tx.Close(); err != nil {
			t.Fatalf("Failed to close transaction: %s", err.Error())
		}
	}
}

func TestResponseBodyForceProcessing(t *testing.T) {
	waf := NewWAF()
	waf.ResponseBodyAccess = true
	tx := waf.NewTransaction()
	tx.ForceResponseBodyVariable = true
	tx.variables.ResponseBodyProcessor().(*collections.Single).Set("JSON")
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	tx.ProcessResponseHeaders(200, "HTTP/1")
	if _, _, err := tx.WriteResponseBody([]byte(`{"key":"value"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Fatal(err)
	}
	f := tx.variables.responseArgs.FindString("json.key")
	if len(f) == 0 {
		t.Fatal("json.key not found")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestForceRequestBodyOverride(t *testing.T) {
	waf := NewWAF()
	waf.RequestBodyAccess = true
	tx := waf.NewTransaction()
	tx.ForceRequestBodyVariable = true
	tx.variables.RequestBodyProcessor().(*collections.Single).Set("JSON")
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody([]byte("foo=bar&baz=qux")); err != nil {
		t.Fatalf("Failed to write request body: %v", err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("Failed to process request body: %v", err)
	}
	if tx.variables.RequestBodyProcessor().Get() != "JSON" {
		t.Fatalf("Failed to force request body variable")
	}
	tx = waf.NewTransaction()
	tx.ForceRequestBodyVariable = true
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody([]byte("foo=bar&baz=qux")); err != nil {
		t.Fatalf("Failed to write request body: %v", err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("Failed to process request body: %v", err)
	}
	if tx.variables.RequestBodyProcessor().Get() != "URLENCODED" {
		t.Fatalf("Failed to force request body variable, got RBP: %q", tx.variables.RequestBodyProcessor().Get())
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestGetUnixTimestamp(t *testing.T) {
	tx := makeTransaction(t)
	stamp := tx.UnixTimestamp()
	t.Logf("stamp: %d", stamp)
	if stamp <= 0 {
		t.Fatalf("no timestamp found")
	}
}

func TestCloseFails(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	col := tx.Variables().FilesTmpNames().(*collections.Map)
	col.Add("", "unexisting")
	err := tx.Close()
	if err == nil {
		t.Fatalf("expected error when closing transaction")
	}

	if !strings.Contains(err.Error(), "removing temporary file") {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
}
