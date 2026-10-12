// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/internal/environment"
	"github.com/corazawaf/coraza/v3/internal/operators"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/internal/transformations"
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

func TestTxTime(t *testing.T) {
	tx := makeTransactionTimestamped(t)
	exp := map[string]string{
		"%{TIME}":       "15:27:34",
		"%{TIME_DAY}":   "18",
		"%{TIME_EPOCH}": fmt.Sprintf("%d", tx.Timestamp/1e9), // 1731943654 in UTC, may differ in local timezone
		"%{TIME_HOUR}":  "15",
		"%{TIME_MIN}":   "27",
		"%{TIME_MON}":   "11",
		"%{TIME_SEC}":   "34",
		"%{TIME_WDAY}":  "1",
		"%{TIME_YEAR}":  "2024",
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

func TestAuditLogPartJWithMultipartFiles(t *testing.T) {
	tx := makeTransactionMultipart(t)
	tx.AuditLogParts = types.AuditLogParts("AJZ")
	_, err := tx.ProcessRequestBody()
	if err != nil {
		t.Fatal(err)
	}
	al := tx.AuditLog()

	if !al.Transaction().HasRequest() {
		t.Fatal("expected request in audit log")
	}

	files := al.Transaction().Request().Files()
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}

	// Files come from the multipart body: a.txt and a.html
	names := map[string]bool{}
	for _, f := range files {
		names[f.Name()] = true
		if f.Size() == 0 {
			t.Errorf("file %s has size 0", f.Name())
		}
	}
	if !names["a.txt"] {
		t.Error("missing file a.txt")
	}
	if !names["a.html"] {
		t.Error("missing file a.html")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestAuditLogPartJWithoutFiles(t *testing.T) {
	tx := makeTransaction(t)
	tx.AuditLogParts = types.AuditLogParts("AJZ")
	al := tx.AuditLog()

	if !al.Transaction().HasRequest() {
		t.Fatal("expected request in audit log")
	}

	files := al.Transaction().Request().Files()
	if len(files) != 0 {
		t.Fatalf("expected 0 files, got %d", len(files))
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestAuditLogPartJFileSizeParseError(t *testing.T) {
	tx := makeTransaction(t)
	tx.AuditLogParts = types.AuditLogParts("AJZ")

	// Manually inject a file with an unparseable size
	tx.variables.files.Add("", "bad_size.bin")
	tx.variables.filesSizes.SetIndex("bad_size.bin", 0, "not_a_number")

	al := tx.AuditLog()
	files := al.Transaction().Request().Files()
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Name() != "bad_size.bin" {
		t.Errorf("expected file name bad_size.bin, got %s", files[0].Name())
	}
	// Size should default to 0 on parse error
	if files[0].Size() != 0 {
		t.Errorf("expected size 0 on parse error, got %d", files[0].Size())
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

var responseBodyWriters = map[string]func(tx *Transaction, body string) (*types.Interruption, int, error){
	"WriteResponseBody": func(tx *Transaction, body string) (*types.Interruption, int, error) {
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
	rule.Audit = true
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

func TestAuditLogMessageFiltering(t *testing.T) {
	tests := []struct {
		name           string
		log            bool
		audit          bool
		wantInAuditLog bool
		wantInErrorLog bool
		desc           string
	}{
		{
			name:           "log action (log=true, audit=true)",
			log:            true,
			audit:          true,
			wantInAuditLog: true,
			wantInErrorLog: true,
			desc:           "log sets both flags: rule appears in error log and audit log",
		},
		{
			name:           "nolog action (log=false, audit=false)",
			log:            false,
			audit:          false,
			wantInAuditLog: false,
			wantInErrorLog: false,
			desc:           "nolog clears both flags: rule appears in neither",
		},
		{
			name:           "nolog,auditlog (log=false, audit=true)",
			log:            false,
			audit:          true,
			wantInAuditLog: true,
			wantInErrorLog: false,
			desc:           "nolog,auditlog: rule appears in audit log only",
		},
		{
			name:           "log,noauditlog (log=true, audit=false)",
			log:            true,
			audit:          false,
			wantInAuditLog: false,
			wantInErrorLog: true,
			desc:           "log,noauditlog: rule appears in error log only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := makeTransaction(t)
			tx.AuditLogParts = types.AuditLogParts("ABCDEFGHIJK")

			var errorLogCalled bool
			tx.WAF.ErrorLogCb = func(_ types.MatchedRule) {
				errorLogCalled = true
			}

			rule := NewRule()
			rule.ID_ = 100
			rule.Log = tt.log
			rule.Audit = tt.audit
			tx.MatchRule(rule, []types.MatchData{
				&corazarules.MatchData{
					Variable_: variables.UniqueID,
				},
			})

			al := tx.AuditLog()

			if got := len(al.Messages()) > 0; got != tt.wantInAuditLog {
				t.Errorf("%s: audit log messages: got present=%v, want present=%v", tt.desc, got, tt.wantInAuditLog)
			}

			if errorLogCalled != tt.wantInErrorLog {
				t.Errorf("%s: error log callback: got called=%v, want called=%v", tt.desc, errorLogCalled, tt.wantInErrorLog)
			}

			if err := tx.Close(); err != nil {
				t.Fatalf("Failed to close transaction: %s", err.Error())
			}
		})
	}
}

func TestAuditLogHPartMessageFiltering(t *testing.T) {
	// When only H (AuditLogTrailer) is set without K (RulesMatched),
	// error messages should still be filtered by the Audit flag.
	tests := []struct {
		name           string
		log            bool
		audit          bool
		wantInAuditLog bool
	}{
		{
			name:           "log,audit: appears in H-only messages",
			log:            true,
			audit:          true,
			wantInAuditLog: true,
		},
		{
			name:           "log,noaudit: excluded from H-only messages",
			log:            true,
			audit:          false,
			wantInAuditLog: false,
		},
		{
			name:           "nolog,audit: appears in H-only messages",
			log:            false,
			audit:          true,
			wantInAuditLog: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := makeTransaction(t)
			// H without K
			tx.AuditLogParts = types.AuditLogParts("ABCDEFGH")

			rule := NewRule()
			rule.ID_ = 200
			rule.Log = tt.log
			rule.Audit = tt.audit
			tx.MatchRule(rule, []types.MatchData{
				&corazarules.MatchData{
					Variable_: variables.UniqueID,
				},
			})

			al := tx.AuditLog()

			if got := len(al.Messages()) > 0; got != tt.wantInAuditLog {
				t.Errorf("H-only audit log: got present=%v, want present=%v", got, tt.wantInAuditLog)
			}

			if err := tx.Close(); err != nil {
				t.Fatalf("Failed to close transaction: %s", err.Error())
			}
		})
	}
}

func TestMatchRuleDisruptiveActionPopulated(t *testing.T) {
	tests := []struct {
		name                         string
		engine                       types.RuleEngineStatus
		wantDisruptive               bool
		wantAction                   corazarules.DisruptiveAction
		wantInterrupted              bool
		wantDetectionOnlyInterrupted bool
	}{
		{
			name:                         "engine on",
			engine:                       types.RuleEngineOn,
			wantDisruptive:               true,
			wantAction:                   corazarules.DisruptiveActionDeny,
			wantInterrupted:              true,
			wantDetectionOnlyInterrupted: false,
		},
		{
			name:                         "engine detection only",
			engine:                       types.RuleEngineDetectionOnly,
			wantDisruptive:               false,
			wantAction:                   corazarules.DisruptiveActionDeny,
			wantInterrupted:              false,
			wantDetectionOnlyInterrupted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := NewWAF()
			tx := waf.NewTransaction()
			tx.RuleEngine = tt.engine

			rule := NewRule()
			rule.ID_ = 1
			if err := rule.AddVariable(variables.ArgsGet, "", false); err != nil {
				t.Fatal(err)
			}
			rule.SetOperator(&dummyEqOperator{}, "@eq", "0")
			_ = rule.AddAction("deny", &dummyDenyAction{})

			tx.AddGetRequestArgument("test", "0")

			var matchedValues []types.MatchData
			rule.doEvaluate(debuglog.Noop(), types.PhaseRequestHeaders, tx, &matchedValues, 0, tx.transformationCache)

			if len(tx.matchedRules) != 1 {
				t.Fatalf("expected 1 matched rule, got %d", len(tx.matchedRules))
			}
			mr := tx.matchedRules[0].(*corazarules.MatchedRule)
			if mr.Disruptive_ != tt.wantDisruptive {
				t.Errorf("Disruptive_: got %t, want %t", mr.Disruptive_, tt.wantDisruptive)
			}
			if mr.DisruptiveAction_ != tt.wantAction {
				t.Errorf("DisruptiveAction_: got %d, want %d", mr.DisruptiveAction_, tt.wantAction)
			}
			if tx.IsInterrupted() != tt.wantInterrupted {
				t.Errorf("IsInterrupted: got %t, want %t", tx.IsInterrupted(), tt.wantInterrupted)
			}
			if tx.IsDetectionOnlyInterrupted() != tt.wantDetectionOnlyInterrupted {
				t.Errorf("IsDetectionOnlyInterrupted: got %t, want %t", tx.IsDetectionOnlyInterrupted(), tt.wantDetectionOnlyInterrupted)
			}
		})
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

func TestRelevantAuditLoggingWithoutAuditFlag(t *testing.T) {
	// Regression test for https://github.com/corazawaf/coraza/issues/1576
	// When tx.audit is false (no rule with auditlog action matched),
	// SecAuditLogRelevantStatus should still cause logging if the status matches.
	tests := []struct {
		name         string
		status       string
		audit        bool
		interruption *types.Interruption
		shouldLog    bool
	}{
		{
			name:      "audit=false, relevant status via response → should log",
			status:    "403",
			audit:     false,
			shouldLog: true,
		},
		{
			name:      "audit=false, non-relevant status → should not log",
			status:    "200",
			audit:     false,
			shouldLog: false,
		},
		{
			name:  "audit=false, relevant status via interruption → should log",
			audit: false,
			interruption: &types.Interruption{
				Status: 403,
				Action: "deny",
			},
			shouldLog: true,
		},
		{
			name:      "audit=true, relevant status → should log",
			status:    "403",
			audit:     true,
			shouldLog: true,
		},
		{
			name:      "audit=true, non-relevant status → should not log",
			status:    "200",
			audit:     true,
			shouldLog: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := makeTransaction(t)
			debugLog := bytes.Buffer{}
			tx.debugLogger = debuglog.Default().WithLevel(debuglog.LevelDebug).WithOutput(&debugLog)
			tx.WAF.AuditLogRelevantStatus = regexp.MustCompile(`^(?:5|4[0-9][0-35-9])`)
			tx.variables.responseStatus.Set(tt.status)
			tx.interruption = tt.interruption
			tx.AuditEngine = types.AuditEngineRelevantOnly
			tx.audit = tt.audit
			tx.ProcessLogging()
			if err := tx.Close(); err != nil {
				t.Error(err)
			}
			logged := strings.Contains(debugLog.String(), "Transaction marked for audit logging")
			if tt.shouldLog && !logged {
				t.Errorf("expected transaction to be audit logged, debug: %q", debugLog.String())
			}
			if !tt.shouldLog && logged {
				t.Errorf("expected transaction NOT to be audit logged, debug: %q", debugLog.String())
			}
		})
	}
}

// TestTransactionFieldCount is a tripwire against pool-reuse state leaks such as
// https://github.com/corazawaf/coraza/issues/1640. Transactions are pooled and
// reused, so every field must be reset before a transaction is handed out again
// (in newTransaction, or in place in Close); a field left set leaks into the next
// request. This test fails whenever a field is added to or removed from
// Transaction: when it does, make sure the field is reset on pool reuse, then
// update wantFields.
func TestTransactionFieldCount(t *testing.T) {
	const wantFields = 36
	if got := reflect.TypeFor[Transaction]().NumField(); got != wantFields {
		t.Fatalf("Transaction has %d fields, want %d. If you added a field, make sure it "+
			"is reset on pool reuse in newTransaction() (or Close()), then update wantFields.", got, wantFields)
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
	all := col.FindAll()
	values := make([]string, 0, len(all))
	for _, v := range all {
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

// TestDuplicateContentTypeHeaderUsesFirstForBodyProcessorSelection is a
// regression test for GHSA-w253-m66g-rx24: it needs two Content-Type headers
// on one request, which testing/profile's StageInput.Headers
// (map[string]string) cannot express, so it cannot be a profile.
//
// It is also the home for how a single Content-Type value selects the
// processor: leading Unicode whitespace is trimmed as mime.ParseMediaType does.
//
// Only the first Content-Type header may select the body processor, matching
// ProcessRequestBody's mimeType and a typical backend's Header.Get. Otherwise
// e.g. a genuine multipart body gets the URLENCODED processor, which parses
// it without error and leaves ARGS_POST and FILES empty.
func TestDuplicateContentTypeHeaderUsesFirstForBodyProcessorSelection(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    string
	}{
		{"single urlencoded", []string{"application/x-www-form-urlencoded"}, "URLENCODED"},
		{"multipart then urlencoded", []string{"multipart/form-data; boundary=XyZ", "application/x-www-form-urlencoded"}, "MULTIPART"},
		{"urlencoded then multipart", []string{"application/x-www-form-urlencoded", "multipart/form-data; boundary=XyZ"}, "URLENCODED"},
		{"unrecognized then multipart", []string{"text/plain", "multipart/form-data; boundary=XyZ"}, ""},
		{"json then urlencoded", []string{"application/json", "application/x-www-form-urlencoded"}, ""},
		// mime.ParseMediaType (and so the backend) trims Unicode whitespace
		// around the media type; selection must too.
		{"U+0085 before urlencoded", []string{"\u0085application/x-www-form-urlencoded"}, "URLENCODED"},
		{"U+00A0 before urlencoded", []string{"\u00a0application/x-www-form-urlencoded"}, "URLENCODED"},
		{"U+3000 before multipart", []string{"\u3000multipart/form-data; boundary=XyZ"}, "MULTIPART"},
		{"tab before multipart", []string{"\tmultipart/form-data; boundary=XyZ"}, "MULTIPART"},
		{"non-space prefix before urlencoded", []string{"xapplication/x-www-form-urlencoded"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := NewWAF().NewTransaction()
			defer func() { _ = tx.Close() }()
			for _, h := range tt.headers {
				tx.AddRequestHeader("Content-Type", h)
			}
			if got := tx.variables.reqbodyProcessor.Get(); got != tt.want {
				t.Errorf("reqbodyProcessor = %q, want %q", got, tt.want)
			}
		})
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
	for i := range 1000 {
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

func TestCollectionReturnsExpectedTypes(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	defer tx.Close()

	// Dynamically iterate over all possible RuleVariable values so this test
	// stays in sync when new variables are added.
	for i := range 256 {
		v := variables.RuleVariable(i)
		name := v.Name()

		if name == "UNKNOWN" || name == "INVALID_VARIABLE" {
			continue
		}

		c := tx.Collection(v)

		// JSON is explicitly unimplemented (returns nil).
		if v == variables.JSON {
			if c != nil {
				t.Errorf("Collection(%s) should return nil, got %v", name, c)
			}
			continue
		}

		// Variables that exist in the variables package but are not backed by
		// a collection in Transaction.Collection() fall through to the default
		// Noop case. We just verify they don't panic.
		if c == nil {
			t.Errorf("Collection(%s) returned nil, expected non-nil collection", name)
		}
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

func BenchmarkTxGetField(b *testing.B) {
	tx := makeTransaction(b)
	rvp := ruleVariableParams{
		Variable: variables.Args,
	}
	for b.Loop() {
		tx.GetField(rvp)
	}
	if err := tx.Close(); err != nil {
		b.Fatalf("Failed to close transaction: %s", err.Error())
	}
	b.ReportAllocs()
}

// makeTransactionWithJSONArgs creates a transaction that includes JSON-array-style
// GET arguments (json.0.field … json.9.field) on top of the standard args.
// This simulates the real-world pattern that motivates regex key exceptions.
func makeTransactionWithJSONArgs(t testing.TB) *Transaction {
	t.Helper()
	tx := makeTransaction(t)
	for i := 0; i < 10; i++ {
		tx.AddGetRequestArgument(fmt.Sprintf("json.%d.jobdescription", i), "value")
	}
	return tx
}

// BenchmarkTxGetFieldWithShortRegexException measures the overhead of GetField
// when a short regex exception (e.g. ^id$) is applied against the args collection.
func BenchmarkTxGetFieldWithShortRegexException(b *testing.B) {
	tx := makeTransactionWithJSONArgs(b)
	rvp := ruleVariableParams{
		Variable: variables.Args,
		Exceptions: []ruleVariableException{
			{KeyRx: regexp.MustCompile(`^id$`)},
		},
	}
	b.ReportAllocs()

	for b.Loop() {
		tx.GetField(rvp)
	}
	b.StopTimer()
	if err := tx.Close(); err != nil {
		b.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

// BenchmarkTxGetFieldWithMediumRegexException measures the overhead of GetField
// when a medium-complexity regex exception (e.g. ^json\.\d+\.jobdescription$) is
// applied — the typical pattern used in URI-scoped CRS exclusions.
func BenchmarkTxGetFieldWithMediumRegexException(b *testing.B) {
	tx := makeTransactionWithJSONArgs(b)
	rvp := ruleVariableParams{
		Variable: variables.Args,
		Exceptions: []ruleVariableException{
			{KeyRx: regexp.MustCompile(`^json\.\d+\.jobdescription$`)},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx.GetField(rvp)
	}
	b.StopTimer()
	if err := tx.Close(); err != nil {
		b.Fatalf("Failed to close transaction: %s", err.Error())
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
	for b.Loop() {
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

func makeTransactionTimestamped(t testing.TB) *Transaction {
	t.Helper()
	tx := NewWAF().NewTransaction()
	timestamp, err := time.ParseInLocation(time.DateTime, "2024-11-18 15:27:34", time.Local)
	if err != nil {
		panic(err)
	}
	tx.Timestamp = timestamp.UnixNano()
	tx.setTimeVariables()
	return tx
}

func BenchmarkTransactionTimestamped(b *testing.B) {
	tx := NewWAF().NewTransaction()
	tx.Timestamp = time.Now().Unix()

	for b.Loop() {
		tx.setTimeVariables()
	}
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

// TestExtractGetArgumentsDeterministicTruncation asserts that when the query
// string holds more distinct keys than SecArgumentsLimit, the same keys
// survive on every run: arguments are consumed in document order rather than
// Go map order, the trailing ones are dropped instead of stored, and
// REQBODY_ERROR reports the cut.
func TestExtractGetArgumentsDeterministicTruncation(t *testing.T) {
	const uri = "evil=%3Cscript%3E&a=1&b=2&c=3&d=4"
	for i := 0; i < 50; i++ {
		waf := NewWAF()
		waf.ArgumentLimit = 2
		tx := waf.NewTransaction()
		tx.ExtractGetArguments(uri)
		if want, have := 1, len(tx.variables.argsGet.Get("evil")); want != have {
			t.Fatalf("run %d: 'evil' not kept in document order, want %d value, have %d", i, want, have)
		}
		if want, have := 1, len(tx.variables.argsGet.Get("a")); want != have {
			t.Fatalf("run %d: 'a' not kept in document order, want %d value, have %d", i, want, have)
		}
		if want, have := waf.ArgumentLimit, tx.variables.argsGet.Len(); want != have {
			t.Fatalf("run %d: ARGS_GET must hold exactly the limit, want %d values, have %d", i, want, have)
		}
		for _, dropped := range []string{"b", "c", "d"} {
			if have := tx.variables.argsGet.Get(dropped); len(have) != 0 {
				t.Fatalf("run %d: %q is past the limit and must not be stored, have %v", i, dropped, have)
			}
		}
		if want, have := "1", tx.variables.reqbodyError.Get(); want != have {
			t.Fatalf("run %d: unexpected REQBODY_ERROR, want %q, have %q", i, want, have)
		}
		if want, have := argumentsLimitErrorMsg, tx.variables.reqbodyErrorMsg.Get(); want != have {
			t.Fatalf("run %d: unexpected REQBODY_ERROR_MSG, want %q, have %q", i, want, have)
		}
		if err := tx.Close(); err != nil {
			t.Fatalf("Failed to close transaction: %s", err.Error())
		}
	}
}

// TestArgumentsLimitCountsRepeatedKeys asserts that every value counts against
// SecArgumentsLimit, not every distinct name. ModSecurity counts one argument
// table entry per key=value pair, so a query string that stores all its values
// under a single name is capped like any other.
func TestArgumentsLimitCountsRepeatedKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		fill func(tx *Transaction, values int)
		get  func(tx *Transaction) []string
	}{
		{
			name: "extract_get",
			fill: func(tx *Transaction, values int) {
				pairs := make([]string, 0, values)
				for i := 0; i < values; i++ {
					pairs = append(pairs, fmt.Sprintf("a=%d", i))
				}
				tx.ExtractGetArguments(strings.Join(pairs, "&"))
			},
			get: func(tx *Transaction) []string { return tx.variables.argsGet.Get("a") },
		},
		{
			name: "add_get",
			fill: func(tx *Transaction, values int) {
				for i := 0; i < values; i++ {
					tx.AddGetRequestArgument("a", strconv.Itoa(i))
				}
			},
			get: func(tx *Transaction) []string { return tx.variables.argsGet.Get("a") },
		},
		{
			name: "add_post",
			fill: func(tx *Transaction, values int) {
				for i := 0; i < values; i++ {
					tx.AddPostRequestArgument("a", strconv.Itoa(i))
				}
			},
			get: func(tx *Transaction) []string { return tx.variables.argsPost.Get("a") },
		},
		{
			name: "add_path",
			fill: func(tx *Transaction, values int) {
				for i := 0; i < values; i++ {
					tx.AddPathRequestArgument("a", strconv.Itoa(i))
				}
			},
			get: func(tx *Transaction) []string { return tx.variables.argsPath.Get("a") },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			waf := NewWAF()
			waf.ArgumentLimit = 3
			tx := waf.NewTransaction()
			tc.fill(tx, 10)
			if want, have := waf.ArgumentLimit, len(tc.get(tx)); want != have {
				t.Errorf("repeated key stored past the limit, want %d values, have %d", want, have)
			}
			if want, have := "1", tx.variables.reqbodyError.Get(); want != have {
				t.Errorf("unexpected REQBODY_ERROR, want %q, have %q", want, have)
			}
			if want, have := argumentsLimitErrorMsg, tx.variables.reqbodyErrorMsg.Get(); want != have {
				t.Errorf("unexpected REQBODY_ERROR_MSG, want %q, have %q", want, have)
			}
			if err := tx.Close(); err != nil {
				t.Fatalf("Failed to close transaction: %s", err.Error())
			}
		})
	}

	t.Run("add_response", func(t *testing.T) {
		waf := NewWAF()
		waf.ArgumentLimit = 3
		tx := waf.NewTransaction()
		for i := 0; i < 10; i++ {
			tx.AddResponseArgument("a", strconv.Itoa(i))
		}
		if want, have := waf.ArgumentLimit, len(tx.variables.responseArgs.Get("a")); want != have {
			t.Errorf("repeated key stored past the limit, want %d values, have %d", want, have)
		}
		if want, have := "1", tx.variables.resBodyError.Get(); want != have {
			t.Errorf("unexpected RES_BODY_ERROR, want %q, have %q", want, have)
		}
		if want, have := argumentsLimitErrorMsg, tx.variables.resBodyErrorMsg.Get(); want != have {
			t.Errorf("unexpected RES_BODY_ERROR_MSG, want %q, have %q", want, have)
		}
		if err := tx.Close(); err != nil {
			t.Fatalf("Failed to close transaction: %s", err.Error())
		}
	})
}

// queryString builds a url encoded query string holding keys distinct keys.
func queryString(keys int) string {
	pairs := make([]string, 0, keys)
	for i := 0; i < keys; i++ {
		pairs = append(pairs, fmt.Sprintf("k%d=v", i))
	}
	return strings.Join(pairs, "&")
}

// TestArgumentsLimitRaisesReqbodyError asserts that dropping arguments at
// SecArgumentsLimit raises the body error flag and message in every collection
// that caps, with the message ModSecurity reports. The dropped arguments are
// the attacker-chosen tail, so the truncation has to be visible to the rules
// and not only to the debug log. RESPONSE_ARGS is filled while the response is
// processed, so it reports through RES_BODY_ERROR; every other collection
// reports through REQBODY_ERROR.
func TestArgumentsLimitRaisesReqbodyError(t *testing.T) {
	// Spelled out once: this is the text ModSecurity emits, and a ruleset
	// matching on it verbatim breaks if it drifts.
	if want, have := "SecArgumentsLimit exceeded", argumentsLimitErrorMsg; want != have {
		t.Fatalf("the message no longer matches ModSecurity, want %q, have %q", want, have)
	}
	for _, tc := range []struct {
		name         string
		responseSide bool
		fill         func(tx *Transaction, keys int)
	}{
		{
			name: "extract_get",
			fill: func(tx *Transaction, keys int) {
				tx.ExtractGetArguments(queryString(keys))
			},
		},
		{
			name: "process_uri",
			fill: func(tx *Transaction, keys int) {
				tx.ProcessURI("/?"+queryString(keys), "GET", "HTTP/1.1")
			},
		},
		{
			name: "add_get",
			fill: func(tx *Transaction, keys int) {
				for i := 0; i < keys; i++ {
					tx.AddGetRequestArgument(fmt.Sprintf("k%d", i), "v")
				}
			},
		},
		{
			name: "add_path",
			fill: func(tx *Transaction, keys int) {
				for i := 0; i < keys; i++ {
					tx.AddPathRequestArgument(fmt.Sprintf("k%d", i), "v")
				}
			},
		},
		{
			name: "add_post",
			fill: func(tx *Transaction, keys int) {
				for i := 0; i < keys; i++ {
					tx.AddPostRequestArgument(fmt.Sprintf("k%d", i), "v")
				}
			},
		},
		{
			name:         "add_response",
			responseSide: true,
			fill: func(tx *Transaction, keys int) {
				for i := 0; i < keys; i++ {
					tx.AddResponseArgument(fmt.Sprintf("k%d", i), "v")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, c := range []struct {
				keys    int
				want    string
				wantMsg string
			}{
				{keys: 3, want: "0", wantMsg: ""},
				{keys: 4, want: "1", wantMsg: argumentsLimitErrorMsg},
			} {
				waf := NewWAF()
				waf.ArgumentLimit = 3
				tx := waf.NewTransaction()
				tc.fill(tx, c.keys)

				flagName, msgName := "REQBODY_ERROR", "REQBODY_ERROR_MSG"
				flag, msg := tx.variables.reqbodyError, tx.variables.reqbodyErrorMsg
				quiet, quietName := tx.variables.resBodyError, "RES_BODY_ERROR"
				if tc.responseSide {
					flagName, msgName = "RES_BODY_ERROR", "RES_BODY_ERROR_MSG"
					flag, msg = tx.variables.resBodyError, tx.variables.resBodyErrorMsg
					quiet, quietName = tx.variables.reqbodyError, "REQBODY_ERROR"
				}
				if have := flag.Get(); c.want != have {
					t.Errorf("%d keys under a limit of 3: unexpected %s, want %q, have %q", c.keys, flagName, c.want, have)
				}
				if have := msg.Get(); c.wantMsg != have {
					t.Errorf("%d keys under a limit of 3: unexpected %s, want %q, have %q", c.keys, msgName, c.wantMsg, have)
				}
				// The two sides report independently: a cap on one must not
				// make a rule on the other match.
				if want, have := "0", quiet.Get(); want != have {
					t.Errorf("%d keys under a limit of 3: truncation must not touch %s, want %q, have %q", c.keys, quietName, want, have)
				}
				if err := tx.Close(); err != nil {
					t.Fatalf("Failed to close transaction: %s", err.Error())
				}
			}
		})
	}
}

// TestBodylessRequestOverArgumentsLimitRaisesReqbodyError asserts that a
// request carrying no body at all raises REQBODY_ERROR once its query string
// alone passes SecArgumentsLimit. The query string caps the same way a body
// does and reports through the same variables, as ModSecurity does, so a
// ruleset written against REQBODY_ERROR sees query-string truncation too.
func TestBodylessRequestOverArgumentsLimitRaisesReqbodyError(t *testing.T) {
	waf := NewWAF()
	waf.ArgumentLimit = 3
	tx := waf.NewTransaction()
	tx.ProcessURI("/?"+queryString(4), "GET", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	if want, have := "1", tx.variables.reqbodyError.Get(); want != have {
		t.Errorf("unexpected REQBODY_ERROR, want %q, have %q", want, have)
	}
	if want, have := argumentsLimitErrorMsg, tx.variables.reqbodyErrorMsg.Get(); want != have {
		t.Errorf("unexpected REQBODY_ERROR_MSG, want %q, have %q", want, have)
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

// TestArgumentsLimitKeepsFirstBodyErrorMessage asserts that an argument limit
// trip leaves a message a parse failure already set alone, so the more
// specific diagnosis is the one an operator reads.
func TestArgumentsLimitKeepsFirstBodyErrorMessage(t *testing.T) {
	waf := NewWAF()
	waf.RequestBodyAccess = true
	waf.ArgumentLimit = 2
	tx := waf.NewTransaction()
	tx.AddRequestHeader("content-type", "application/xml")
	tx.ProcessRequestHeaders()
	tx.variables.reqbodyProcessor.Set("XML")
	if _, err := tx.requestBodyBuffer.Write([]byte("<root><1a/></root>")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	want := tx.variables.reqbodyErrorMsg.Get()
	if want == "" || strings.Contains(want, argumentsLimitErrorMsg) {
		t.Fatalf("the malformed body did not report a parse failure, REQBODY_ERROR_MSG is %q", want)
	}

	for i := 0; i <= waf.ArgumentLimit; i++ {
		tx.AddPostRequestArgument(fmt.Sprintf("k%d", i), "v")
	}
	if have := tx.variables.reqbodyErrorMsg.Get(); want != have {
		t.Errorf("the argument limit overwrote the parse failure message, want %q, have %q", want, have)
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

// TestBodyErrorMessageFollowsTheLatestParseFailure asserts that a parse failure
// replaces a message an argument limit trip already set. The write-once guard
// is deliberately one-directional, as in ModSecurity, where it lives inside
// add_argument() alone: a truncation notice gives way to the parser's own
// diagnosis, while the reverse order keeps the parse failure.
func TestBodyErrorMessageFollowsTheLatestParseFailure(t *testing.T) {
	waf := NewWAF()
	waf.RequestBodyAccess = true
	waf.ArgumentLimit = 2
	tx := waf.NewTransaction()
	tx.ProcessURI("/?a=1&b=2&c=3", "GET", "HTTP/1.1")
	if want, have := argumentsLimitErrorMsg, tx.variables.reqbodyErrorMsg.Get(); want != have {
		t.Fatalf("the query string did not trip the limit, REQBODY_ERROR_MSG is %q, want %q", have, want)
	}

	tx.AddRequestHeader("content-type", "application/xml")
	tx.ProcessRequestHeaders()
	tx.variables.reqbodyProcessor.Set("XML")
	if _, err := tx.requestBodyBuffer.Write([]byte("<root><1a/></root>")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	have := tx.variables.reqbodyErrorMsg.Get()
	if have == "" || strings.Contains(have, argumentsLimitErrorMsg) {
		t.Errorf("the parse failure did not replace the truncation notice, REQBODY_ERROR_MSG is %q", have)
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

// TestResponseBodyErrorVariablesAreAddressable asserts that the RES_BODY_ERROR
// family resolves to the collection that holds it. An unmapped variable falls
// back to the noop collection, so a rule written against it compiles and then
// never matches whatever the response path raised.
func TestResponseBodyErrorVariablesAreAddressable(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	for _, tc := range []struct {
		variable variables.RuleVariable
		holder   *collections.Single
	}{
		{variables.ResBodyError, tx.variables.resBodyError},
		{variables.ResBodyErrorMsg, tx.variables.resBodyErrorMsg},
		{variables.ResBodyProcessorError, tx.variables.resBodyProcessorError},
		{variables.ResBodyProcessorErrorMsg, tx.variables.resBodyProcessorErrorMsg},
	} {
		// The value is the variable's own name, so resolving to a sibling of
		// the right shape is a mismatch rather than a coincidence.
		want := tc.variable.Name()
		tc.holder.Set(want)
		var have []string
		for _, md := range tx.Collection(tc.variable).FindAll() {
			have = append(have, md.Value())
		}
		if len(have) != 1 || have[0] != want {
			t.Errorf("a rule on %s cannot see what the response path raised, want [%q], have %q", tc.variable.Name(), want, have)
		}
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

// TestResponseBodyErrorVariablesSeeded asserts that a fresh transaction reads
// "0" from the RES_BODY_ERROR flags, so a rule written as
// `SecRule RES_BODY_ERROR "!@eq 0"` compares against a number on a clean
// response instead of an empty string, as it does on the request side.
func TestResponseBodyErrorVariablesSeeded(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	for _, v := range []struct {
		name string
		have string
	}{
		{"RES_BODY_ERROR", tx.variables.resBodyError.Get()},
		{"RES_BODY_PROCESSOR_ERROR", tx.variables.resBodyProcessorError.Get()},
	} {
		if want := "0"; want != v.have {
			t.Errorf("unexpected %s on a clean response, want %q, have %q", v.name, want, v.have)
		}
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

// TestResponseBodyErrorVariablesMinPhase asserts that the RES_BODY_ERROR family
// is known to be populated in the response body phase. A variable with no phase
// makes a chained rule using it evaluate in every phase, where the flags still
// hold their seeded "0".
func TestResponseBodyErrorVariablesMinPhase(t *testing.T) {
	for _, v := range []variables.RuleVariable{
		variables.ResBodyError,
		variables.ResBodyErrorMsg,
		variables.ResBodyProcessorError,
		variables.ResBodyProcessorErrorMsg,
	} {
		if want, have := types.PhaseResponseBody, minPhase(v); want != have {
			t.Errorf("unexpected min phase for %s, want %d, have %d", v.Name(), want, have)
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

// TestAddArgsRepeatedKeyOverlimit is a regression test for
// GHSA-3ww9-vw83-9w5x: checkArgumentLimit used to compare against Len (the
// number of distinct keys), so many values added under a single repeated key
// never tripped the limit no matter how many times Add was called. It must
// now be bounded by TotalValues (every individual value) instead.
func TestAddArgsRepeatedKeyOverlimit(t *testing.T) {
	const limit = 5
	const attempts = 1000

	adders := map[string]func(tx *Transaction, key, value string){
		"get":      func(tx *Transaction, key, value string) { tx.AddGetRequestArgument(key, value) },
		"post":     func(tx *Transaction, key, value string) { tx.AddPostRequestArgument(key, value) },
		"path":     func(tx *Transaction, key, value string) { tx.AddPathRequestArgument(key, value) },
		"response": func(tx *Transaction, key, value string) { tx.AddResponseArgument(key, value) },
	}

	for name, add := range adders {
		t.Run(name, func(t *testing.T) {
			waf := NewWAF()
			tx := waf.NewTransaction()
			tx.WAF.ArgumentLimit = limit
			for i := 0; i < attempts; i++ {
				add(tx, "repeated", "samplevalue")
			}

			var total int
			switch name {
			case "get":
				total = tx.variables.argsGet.TotalValues()
			case "post":
				total = tx.variables.argsPost.TotalValues()
			case "path":
				total = tx.variables.argsPath.TotalValues()
			case "response":
				total = tx.variables.responseArgs.TotalValues()
			}
			if total > limit {
				t.Fatalf("expected at most %d total values under a repeated key, got %d", limit, total)
			}

			if err := tx.Close(); err != nil {
				t.Fatalf("Failed to close transaction: %s", err.Error())
			}
		})
	}
}

// TestExtractGetArgumentsRepeatedKeyOverlimit confirms ExtractGetArguments
// (the query-string entry point, as opposed to calling AddGetRequestArgument
// directly) is bounded the same way, and sets ARGUMENTS_LIMIT_REACHED.
func TestExtractGetArgumentsRepeatedKeyOverlimit(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.WAF.ArgumentLimit = 5

	uri := "/x?" + strings.TrimSuffix(strings.Repeat("a=1&", 1000), "&")
	tx.ExtractGetArguments(uri)

	if got := tx.variables.argsGet.TotalValues(); got > 5 {
		t.Fatalf("expected at most 5 total ARGS_GET values, got %d", got)
	}
	if tx.variables.argumentsLimitReached.Get() != "1" {
		t.Error("expected ARGUMENTS_LIMIT_REACHED to be set")
	}

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
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
	tx.ProcessResponseHeaders(200, "HTTP/1.1")
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

func TestCloseFails(t *testing.T) {
	if !environment.HasAccessToFS {
		t.Skip("skipping test as it requires access to filesystem")
	}
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

func TestUploadKeepFiles(t *testing.T) {
	if !environment.HasAccessToFS {
		t.Skip("skipping test as it requires access to filesystem")
	}

	createTmpFile := func(t *testing.T) string {
		t.Helper()
		f, err := os.CreateTemp(t.TempDir(), "crztest*")
		if err != nil {
			t.Fatal(err)
		}
		name := f.Name()
		if err := f.Close(); err != nil {
			t.Fatalf("failed to close temp file: %v", err)
		}
		return name
	}

	t.Run("Off deletes files", func(t *testing.T) {
		waf := NewWAF()
		waf.UploadKeepFiles = types.UploadKeepFilesOff
		tx := waf.NewTransaction()
		tmpFile := createTmpFile(t)

		col := tx.Variables().FilesTmpNames().(*collections.Map)
		col.Add("", tmpFile)

		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
			t.Fatal("expected temp file to be deleted when UploadKeepFiles is Off")
		}
	})

	t.Run("On keeps files", func(t *testing.T) {
		waf := NewWAF()
		waf.UploadKeepFiles = types.UploadKeepFilesOn
		tx := waf.NewTransaction()
		tmpFile := createTmpFile(t)

		col := tx.Variables().FilesTmpNames().(*collections.Map)
		col.Add("", tmpFile)

		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := os.Stat(tmpFile); err != nil {
			t.Fatal("expected temp file to be kept when UploadKeepFiles is On")
		}
	})

	t.Run("RelevantOnly keeps files when log rules matched", func(t *testing.T) {
		waf := NewWAF()
		waf.UploadKeepFiles = types.UploadKeepFilesRelevantOnly
		tx := waf.NewTransaction()
		tmpFile := createTmpFile(t)

		// Simulate a matched rule with Log enabled
		tx.matchedRules = append(tx.matchedRules, &corazarules.MatchedRule{Log_: true})

		col := tx.Variables().FilesTmpNames().(*collections.Map)
		col.Add("", tmpFile)

		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := os.Stat(tmpFile); err != nil {
			t.Fatal("expected temp file to be kept when UploadKeepFiles is RelevantOnly and log rules matched")
		}
	})

	t.Run("RelevantOnly deletes files when only nolog rules matched", func(t *testing.T) {
		waf := NewWAF()
		waf.UploadKeepFiles = types.UploadKeepFilesRelevantOnly
		tx := waf.NewTransaction()
		tmpFile := createTmpFile(t)

		// Simulate a matched rule with Log disabled (e.g. CRS initialization rules)
		tx.matchedRules = append(tx.matchedRules, &corazarules.MatchedRule{Log_: false})

		col := tx.Variables().FilesTmpNames().(*collections.Map)
		col.Add("", tmpFile)

		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
			t.Fatal("expected temp file to be deleted when UploadKeepFiles is RelevantOnly and only nolog rules matched")
		}
	})

	t.Run("RelevantOnly deletes files when no rules matched", func(t *testing.T) {
		waf := NewWAF()
		waf.UploadKeepFiles = types.UploadKeepFilesRelevantOnly
		tx := waf.NewTransaction()
		tmpFile := createTmpFile(t)

		col := tx.Variables().FilesTmpNames().(*collections.Map)
		col.Add("", tmpFile)

		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
			t.Fatal("expected temp file to be deleted when UploadKeepFiles is RelevantOnly and no rules matched")
		}
	})
}

func TestCloseReleasesPerRequestReferences(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()

	rule := NewRule()
	rule.ID_ = 1234
	rule.Log = true
	for i := 0; i < 10; i++ {
		tx.MatchRule(rule, []types.MatchData{
			&corazarules.MatchData{
				Variable_: variables.ArgsPost,
				Key_:      "key",
				Value_:    "value",
			},
		})
	}
	tx.detectionOnlyInterruption = &types.Interruption{Status: 403}
	tx.transformationCache[transformationKey{argIndex: 1}] = transformationValue{arg: "value"}
	tx.SetRuleFilter(&RuleFilterWrapper{})

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}

	mrs := tx.matchedRules
	// Reslicing to zero length would keep every matched rule reachable through
	// the backing array, so the slice itself must be released.
	if mrs != nil {
		t.Errorf("expected matched rules to be released after Close, got %d entries with capacity %d", len(mrs), cap(mrs))
	}
	if tx.ruleFilter != nil {
		t.Error("expected ruleFilter to be nil after Close")
	}
	if tx.detectionOnlyInterruption != nil {
		t.Error("expected detectionOnlyInterruption to be nil after Close")
	}
	if tx.context != nil {
		t.Error("expected context to be nil after Close")
	}
	if len(tx.transformationCache) != 0 {
		t.Errorf("expected empty transformation cache after Close, got %d entries", len(tx.transformationCache))
	}
}

func TestCloseKeepsRelevantFilesBeforeReleasingMatchedRules(t *testing.T) {
	if !environment.HasAccessToFS {
		t.Skip("skipping test as it requires access to filesystem")
	}

	waf := NewWAF()
	waf.UploadKeepFiles = types.UploadKeepFilesRelevantOnly
	tx := waf.NewTransaction()

	f, err := os.CreateTemp(t.TempDir(), "crztest*")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile := f.Name()
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	tx.Variables().FilesTmpNames().(*collections.Map).Add("", tmpFile)

	tx.matchedRules = append(tx.matchedRules, &corazarules.MatchedRule{Log_: true})

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}

	if _, err := os.Stat(tmpFile); err != nil {
		t.Fatal("expected temp file to be kept when a log-relevant rule matched")
	}
	if tx.matchedRules != nil {
		t.Error("expected matched rules to be released after Close")
	}
}

func TestTransactionReuseAfterClose(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()

	rule := NewRule()
	rule.ID_ = 1234
	rule.Log = true
	tx.MatchRule(rule, []types.MatchData{
		&corazarules.MatchData{Variable_: variables.UniqueID},
	})
	tx.detectionOnlyInterruption = &types.Interruption{Status: 403}
	tx.ForceRequestBodyVariable = true
	tx.ForceResponseBodyVariable = true

	if err := tx.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}

	tx2 := waf.NewTransaction()
	if len(tx2.matchedRules) != 0 {
		t.Errorf("expected no matched rules on a fresh transaction, got %d", len(tx2.matchedRules))
	}
	if tx2.detectionOnlyInterruption != nil {
		t.Error("expected no detection-only interruption on a fresh transaction")
	}
	// A stale force flag makes the next request buffer and parse a body its own
	// configuration excludes.
	if tx2.ForceRequestBodyVariable {
		t.Error("expected ForceRequestBodyVariable to be unset on a fresh transaction")
	}
	if tx2.ForceResponseBodyVariable {
		t.Error("expected ForceResponseBodyVariable to be unset on a fresh transaction")
	}
	if tx2.context == nil {
		t.Error("expected a fresh transaction to have a context")
	}

	tx2.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 80)
	tx2.ProcessURI("/test", "GET", "HTTP/1.1")
	if it := tx2.ProcessRequestHeaders(); it != nil {
		t.Errorf("unexpected interruption on a fresh transaction: %+v", it)
	}
	if err := tx2.Close(); err != nil {
		t.Fatalf("Failed to close transaction: %s", err.Error())
	}
}

func TestRequestFilename(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			name:     "simple",
			uri:      "/foo",
			expected: "/foo",
		},
		{
			name:     "with query",
			uri:      "/foo?bar=baz",
			expected: "/foo",
		},
		{
			name:     "with query and fragment",
			uri:      "/foo?bar=baz#qux",
			expected: "/foo",
		},
		{
			name:     "subdirectory",
			uri:      "/foo/bar",
			expected: "/foo/bar",
		},
		{
			name:     "subdirectory with query",
			uri:      "/foo/bar?baz=qux",
			expected: "/foo/bar",
		},
		{
			name:     "multiple leading slashes",
			uri:      "//foo/bar",
			expected: "//foo/bar",
		},
		{
			name:     "multiple leading slashes - 2",
			uri:      "///foo/bar",
			expected: "///foo/bar",
		},
		{ // url.ParseRequestURI fails on invalid percent-encoding; the "?" fallback
			// split still recovers the path/query boundary. See GHSA-x26q-wvhg-fh4m.
			name:     "invalid encoding",
			uri:      "/foo%zz?a=b",
			expected: "/foo%zz",
		},
		{
			name:     "valid encoding",
			uri:      "/foo%20bar",
			expected: "/foo bar",
		},
		{
			name:     "trailing slash",
			uri:      "/foo/bar/",
			expected: "/foo/bar/",
		},
		{
			name:     "duplicated slashes",
			uri:      "//foo//bar",
			expected: "//foo//bar",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			waf := NewWAF()
			tx := waf.NewTransaction()
			tx.ProcessURI(test.uri, http.MethodGet, "HTTP/1.1")
			if tx.variables.requestFilename.Get() != test.expected {
				t.Fatalf("Expected REQUEST_FILENAME %q, got %q", test.expected, tx.variables.requestFilename.Get())
			}
		})
	}
}

// GHSA-x26q-wvhg-fh4m: a URI containing raw control bytes (e.g. a NUL, as a
// non-net/http integration like coraza-spoa or coraza-proxy-wasm might forward)
// fails url.ParseRequestURI, and previously left QUERY_STRING/ARGS_GET empty,
// silently dropping the entire attack payload from GET-side rule matching.
func TestProcessURIFallbackOnParseError(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.ProcessURI("/search?q=ATTACK_HERE_XYZ\x00&y=1", http.MethodGet, "HTTP/1.1")

	if got := tx.variables.uriParseError.Get(); got != "1" {
		t.Errorf("Expected URI_PARSE_ERROR to be \"1\", got %q", got)
	}
	if got := tx.variables.queryString.Get(); got != "q=ATTACK_HERE_XYZ\x00&y=1" {
		t.Errorf("Expected QUERY_STRING to be recovered from the raw URI, got %q", got)
	}
	if got := tx.variables.argsGet.Get("q"); len(got) == 0 || got[0] != "ATTACK_HERE_XYZ\x00" {
		t.Errorf("Expected ARGS_GET q to be populated on best effort, got %v", got)
	}
	if got := tx.variables.requestURIRaw.Get(); got != "/search?q=ATTACK_HERE_XYZ\x00&y=1" {
		t.Errorf("Expected REQUEST_URI_RAW to hold the untouched URI, got %q", got)
	}
}

func BenchmarkRuleEvalWithTransformations(b *testing.B) {
	waf := NewWAF()
	op, err := operators.Get("unconditionalMatch", plugintypes.OperatorOptions{})
	if err != nil {
		b.Fatal(err)
	}
	lowercaseFn, err := transformations.GetTransformation("lowercase")
	if err != nil {
		b.Fatal(err)
	}

	rule := NewRule()
	rule.ID_ = 1000
	rule.LogID_ = "1000"
	rule.Phase_ = types.PhaseRequestHeaders
	rule.operator = &ruleOperatorParams{
		Operator: op,
		Function: "@unconditionalMatch",
	}
	if err := rule.AddTransformation("lowercase", lowercaseFn); err != nil {
		b.Fatal(err)
	}
	rule.variables = append(rule.variables, ruleVariableParams{
		Variable: variables.Args,
	})
	if err := waf.Rules.Add(rule); err != nil {
		b.Fatal(err)
	}

	tx := waf.NewTransaction()
	b.Cleanup(func() {
		if err := tx.Close(); err != nil {
			b.Fatalf("failed to close transaction: %v", err)
		}
	})
	tx.ProcessURI("/test?a=1&b=2&c=3&d=4&e=5", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	if it := tx.ProcessRequestHeaders(); it != nil {
		b.Fatalf("unexpected interruption during request headers processing: %+v", it)
	}
	b.ReportAllocs()

	for b.Loop() {
		waf.Rules.Eval(types.PhaseRequestHeaders, tx)
	}
}

func newTestUnconditionalMatch(t testing.TB) plugintypes.Operator {
	t.Helper()
	op, err := operators.Get("unconditionalMatch", plugintypes.OperatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func TestRemoveRuleByID(t *testing.T) {
	waf := NewWAF()
	op := newTestUnconditionalMatch(t)

	// Add two rules with different IDs
	rule1 := NewRule()
	rule1.ID_ = 100
	rule1.LogID_ = "100"
	rule1.Phase_ = types.PhaseRequestHeaders
	rule1.operator = &ruleOperatorParams{
		Operator: op,
		Function: "@unconditionalMatch",
	}
	rule1.Log = true
	if err := waf.Rules.Add(rule1); err != nil {
		t.Fatal(err)
	}

	rule2 := NewRule()
	rule2.ID_ = 200
	rule2.LogID_ = "200"
	rule2.Phase_ = types.PhaseRequestHeaders
	rule2.operator = &ruleOperatorParams{
		Operator: op,
		Function: "@unconditionalMatch",
	}
	rule2.Log = true
	if err := waf.Rules.Add(rule2); err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	defer tx.Close()

	// Remove rule 100
	tx.RemoveRuleByID(100)

	// Verify the map was lazily initialized
	if tx.ruleRemoveByID == nil {
		t.Fatal("ruleRemoveByID should not be nil after RemoveRuleByID")
	}

	// Remove another rule
	tx.RemoveRuleByID(100) // duplicate removal should be idempotent
	tx.RemoveRuleByID(200)

	if len(tx.ruleRemoveByID) != 2 {
		t.Errorf("expected 2 entries in ruleRemoveByID map, got %d", len(tx.ruleRemoveByID))
	}
}

func TestRemoveRuleByIDRange(t *testing.T) {
	waf := NewWAF()

	// Use nil-operator rules (SecAction-style): they always match regardless of variables.
	for _, id := range []int{100, 150, 200, 300} {
		r := NewRule()
		r.ID_ = id
		r.LogID_ = strconv.Itoa(id)
		r.Phase_ = types.PhaseRequestHeaders
		// nil operator means the rule always matches
		if err := waf.Rules.Add(r); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("range is stored", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		tx.RemoveRuleByIDRange(100, 200)
		if len(tx.ruleRemoveByIDRanges) != 1 {
			t.Fatalf("expected 1 range entry, got %d", len(tx.ruleRemoveByIDRanges))
		}
		if tx.ruleRemoveByIDRanges[0][0] != 100 || tx.ruleRemoveByIDRanges[0][1] != 200 {
			t.Errorf("unexpected range: %v", tx.ruleRemoveByIDRanges[0])
		}
	})

	t.Run("rules in range are skipped during eval", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		// Remove rules with IDs 100-200; rule 300 should still be evaluated.
		tx.RemoveRuleByIDRange(100, 200)
		waf.Rules.Eval(types.PhaseRequestHeaders, tx)

		matchedIDs := make(map[int]bool)
		for _, mr := range tx.MatchedRules() {
			matchedIDs[mr.Rule().ID()] = true
		}

		for _, skipped := range []int{100, 150, 200} {
			if matchedIDs[skipped] {
				t.Errorf("rule %d should have been skipped but was matched", skipped)
			}
		}
		if !matchedIDs[300] {
			t.Errorf("rule 300 should have been matched but was not")
		}
	})

	t.Run("multiple ranges", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		tx.RemoveRuleByIDRange(100, 100)
		tx.RemoveRuleByIDRange(300, 300)
		if len(tx.ruleRemoveByIDRanges) != 2 {
			t.Fatalf("expected 2 range entries, got %d", len(tx.ruleRemoveByIDRanges))
		}

		waf.Rules.Eval(types.PhaseRequestHeaders, tx)

		matchedIDs := make(map[int]bool)
		for _, mr := range tx.MatchedRules() {
			matchedIDs[mr.Rule().ID()] = true
		}
		if matchedIDs[100] {
			t.Error("rule 100 should have been skipped")
		}
		if matchedIDs[300] {
			t.Error("rule 300 should have been skipped")
		}
		if !matchedIDs[150] {
			t.Error("rule 150 should have been matched")
		}
		if !matchedIDs[200] {
			t.Error("rule 200 should have been matched")
		}
	})

	t.Run("range reset on transaction reuse", func(t *testing.T) {
		tx := waf.NewTransaction()
		tx.RemoveRuleByIDRange(100, 200)
		tx.Close()

		// Get a new transaction (pool reuse may return the same object)
		tx2 := waf.NewTransaction()
		defer tx2.Close()

		if len(tx2.ruleRemoveByIDRanges) != 0 {
			t.Errorf("expected ruleRemoveByIDRanges to be reset, got %d entries", len(tx2.ruleRemoveByIDRanges))
		}
	})
}

func BenchmarkRuleEvalWithRemovedRules(b *testing.B) {
	waf := NewWAF()
	op := newTestUnconditionalMatch(b)

	rule := NewRule()
	rule.ID_ = 1000
	rule.LogID_ = "1000"
	rule.Phase_ = types.PhaseRequestHeaders
	rule.operator = &ruleOperatorParams{
		Operator: op,
		Function: "@unconditionalMatch",
	}
	if err := waf.Rules.Add(rule); err != nil {
		b.Fatal(err)
	}

	tx := waf.NewTransaction()
	defer tx.Close()

	for i := 1; i <= 100; i++ {
		tx.RemoveRuleByID(i)
	}

	b.ReportAllocs()

	for b.Loop() {
		waf.Rules.Eval(types.PhaseRequestHeaders, tx)
	}
}

// TestBodyLimitsDoNotLogAtErrorLevel asserts that no limit a client can trip
// with a syntactically valid body produces an error-level log line. Error is
// reserved for bodies the parser could not read, so a client cannot flood the
// log by sending large well-formed input.
func TestBodyLimitsDoNotLogAtErrorLevel(t *testing.T) {
	for _, tc := range []struct {
		name string
		tune func(*WAF)
		body string
	}{
		{
			name: "arguments_limit",
			tune: func(w *WAF) { w.ArgumentLimit = 10 },
			body: `{"a":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]}`,
		},
		{
			name: "json_recursion_limit",
			// Upstream split the depth limit per direction, so tune both.
			tune: func(w *WAF) {
				w.RequestBodyJsonDepthLimit = 20
				w.ResponseBodyJsonDepthLimit = 20
			},
			body: strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40),
		},
		{
			name: "json_decoded_size_limit",
			tune: func(w *WAF) { w.ArgumentLimit = 1000000 },
			body: deepWideJSONBody(200, 400),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var debugLog strings.Builder
			waf := NewWAF()
			waf.RequestBodyAccess = true
			tc.tune(waf)
			tx := waf.NewTransaction()
			tx.debugLogger = debuglog.Default().WithLevel(debuglog.LevelDebug).WithOutput(&debugLog)
			tx.AddRequestHeader("content-type", "application/json")
			tx.ProcessRequestHeaders()
			tx.variables.reqbodyProcessor.Set("JSON")
			if _, err := tx.requestBodyBuffer.Write([]byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.ProcessRequestBody(); err != nil {
				t.Fatal(err)
			}
			// Each body must actually trip its limit, or the assertion below is
			// vacuous.
			if want, have := "1", tx.variables.reqbodyError.Get(); want != have {
				t.Fatalf("the body did not trip the limit, REQBODY_ERROR is %q", have)
			}
			if strings.Contains(debugLog.String(), "[ERROR]") {
				t.Errorf("a client-triggerable limit logged at error level:\n%s", debugLog.String())
			}
		})

		t.Run(tc.name+"_response", func(t *testing.T) {
			var debugLog strings.Builder
			waf := NewWAF()
			waf.ResponseBodyAccess = true
			tc.tune(waf)
			tx := waf.NewTransaction()
			tx.debugLogger = debuglog.Default().WithLevel(debuglog.LevelDebug).WithOutput(&debugLog)
			tx.ForceResponseBodyVariable = true
			tx.variables.ResponseBodyProcessor().(*collections.Single).Set("JSON")
			tx.ProcessRequestHeaders()
			if _, err := tx.ProcessRequestBody(); err != nil {
				t.Fatal(err)
			}
			tx.ProcessResponseHeaders(200, "HTTP/1.1")
			if _, _, err := tx.WriteResponseBody([]byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.ProcessResponseBody(); err != nil {
				t.Fatal(err)
			}
			if want, have := "1", tx.variables.resBodyError.Get(); want != have {
				t.Fatalf("the body did not trip the limit, RES_BODY_ERROR is %q", have)
			}
			if strings.Contains(debugLog.String(), "[ERROR]") {
				t.Errorf("a client-triggerable limit logged at error level:\n%s", debugLog.String())
			}
		})
	}
}

// deepWideJSONBody builds a body that nests to levels and then fans out into
// leaves, so every flattened path shares one long prefix.
func deepWideJSONBody(levels, leaves int) string {
	b := strings.Builder{}
	for i := 0; i < levels; i++ {
		fmt.Fprintf(&b, `{"nesting_level_%d":`, i)
	}
	b.WriteString("{")
	for i := 0; i < leaves; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"leaf_%d":"%s"`, i, strings.Repeat("v", 200))
	}
	b.WriteString("}")
	b.WriteString(strings.Repeat("}", levels))
	return b.String()
}
