// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/macro"
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
		t.Error("Failed to parse multipart request: " + err.Error())
	}
	exp := map[string]string{
		"%{args_post.text}":      "test-value",
		"%{files_combined_size}": "60",
		"%{files}":               "a.html",
		"%{files_names}":         "file1",
	}

	validateMacroExpansion(exp, tx, t)
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

func TestRequestBody(t *testing.T) {
	const (
		urlencodedBody    = "some=result&second=data"
		urlencodedBodyLen = len(urlencodedBody)
	)

	testCases := []struct {
		name                   string
		requestBodyLimit       int
		requestBodyMemoryLimit int
		requestBodyLimitAction types.BodyLimitAction
		shouldInterrupt        bool
	}{
		{
			name:                   "no memory buffer and limit not reach",
			requestBodyMemoryLimit: 0,
			requestBodyLimit:       urlencodedBodyLen + 1,
			requestBodyLimitAction: types.BodyLimitActionReject,
		},
		{
			name:                   "memory buffer and limit not reach",
			requestBodyMemoryLimit: urlencodedBodyLen / 2,
			requestBodyLimit:       urlencodedBodyLen + 2,
			requestBodyLimitAction: types.BodyLimitActionReject,
		},
		{
			name:                   "no memory buffer and limit rejects",
			requestBodyMemoryLimit: 0,
			requestBodyLimit:       urlencodedBodyLen - 5,
			requestBodyLimitAction: types.BodyLimitActionReject,
			shouldInterrupt:        true,
		},
		{
			name:                   "memory buffer and limit rejects",
			requestBodyMemoryLimit: urlencodedBodyLen / 2,
			requestBodyLimit:       urlencodedBodyLen - 5,
			requestBodyLimitAction: types.BodyLimitActionReject,
			shouldInterrupt:        true,
		},
		{
			name:                   "no memory buffer and limit partial processing",
			requestBodyMemoryLimit: 0,
			requestBodyLimit:       urlencodedBodyLen - 1,
			requestBodyLimitAction: types.BodyLimitActionProcessPartial,
		},
		{
			name:                   "no memory buffer and limit partial processing",
			requestBodyMemoryLimit: urlencodedBodyLen / 2,
			requestBodyLimit:       urlencodedBodyLen - 1,
			requestBodyLimitAction: types.BodyLimitActionProcessPartial,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			waf := NewWAF()
			waf.RuleEngine = types.RuleEngineOn
			waf.RequestBodyAccess = true
			waf.RequestBodyLimit = int64(testCase.requestBodyLimit)
			waf.RequestBodyInMemoryLimit = int64(testCase.requestBodyMemoryLimit)
			waf.RequestBodyLimitAction = testCase.requestBodyLimitAction

			tx := waf.NewTransaction()
			tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
			if _, err := tx.RequestBodyBuffer.Write([]byte(urlencodedBody)); err != nil {
				t.Errorf("Failed to write body buffer: %s", err.Error())
			}

			tx.ProcessRequestHeaders()
			if _, err := tx.ProcessRequestBody(); err != nil {
				t.Errorf("Failed to process request body: %s", err.Error())
			}

			if testCase.shouldInterrupt {
				if tx.interruption == nil {
					t.Error("Expected interruption, got nil")
				}
			} else {
				val := tx.variables.argsPost.Get("some")
				if len(val) != 1 || val[0] != "result" {
					t.Errorf("Failed to set urlencoded POST data with arguments: \"%s\"", strings.Join(val, "\", \""))
				}
			}

			_ = tx.Close()
		})
	}
}

func TestResponseHeader(t *testing.T) {
	tx := makeTransaction(t)
	tx.AddResponseHeader("content-type", "test")
	if tx.variables.responseContentType.String() != "test" {
		t.Error("invalid RESPONSE_CONTENT_TYPE after response headers")
	}

	interruption := tx.ProcessResponseHeaders(200, "OK")
	if interruption != nil {
		t.Error("unexpected interruption")
	}
}

func TestProcessRequestHeadersDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff

	if !tx.IsRuleEngineOff() {
		t.Error("expected Engine off")
	}

	_ = tx.ProcessRequestHeaders()
	if tx.LastPhase != 0 { // 0 means no phases have been evaluated
		t.Error("unexpected rule evaluation")
	}
}

func TestProcessRequestBodyDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Error("failed to process request body")
	}
	if tx.LastPhase != 0 {
		t.Error("unexpected rule evaluation")
	}
}

func TestProcessResponseHeadersDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff
	_ = tx.ProcessResponseHeaders(200, "OK")
	if tx.LastPhase != 0 {
		t.Error("unexpected rule evaluation")
	}
}

func TestProcessResponseBodyDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Error("Failed to process response body")
	}
	if tx.LastPhase != 0 {
		t.Error("unexpected rule evaluation")
	}
}

func TestProcessLoggingDoesNoEvaluationOnEngineOff(t *testing.T) {
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineOff
	tx.ProcessLogging()
	if tx.LastPhase != 0 {
		t.Error("unexpected rule evaluation")
	}
}

func TestAuditLog(t *testing.T) {
	tx := makeTransaction(t)
	tx.AuditLogParts = types.AuditLogParts("ABCDEFGHIJK")
	al := tx.AuditLog()
	if al.Transaction.ID != tx.id {
		t.Error("invalid auditlog id")
	}
	// TODO more checks
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func TestResponseBody(t *testing.T) {
	tx := makeTransaction(t)
	tx.ResponseBodyAccess = true
	tx.RuleEngine = types.RuleEngineOn
	tx.AddResponseHeader("content-type", "text/plain")
	if _, err := tx.ResponseBodyBuffer.Write([]byte("test123")); err != nil {
		t.Error("Failed to write response body buffer")
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Error("Failed to process response body")
	}
	if tx.variables.responseBody.String() != "test123" {
		t.Error("failed to set response body")
	}
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func TestAuditLogFields(t *testing.T) {
	tx := makeTransaction(t)
	tx.AuditLogParts = types.AuditLogParts("ABCDEFGHIJK")
	tx.AddRequestHeader("test", "test")
	tx.AddResponseHeader("test", "test")
	rule := NewRule()
	rule.ID_ = 131
	tx.MatchRule(rule, []types.MatchData{
		&corazarules.MatchData{
			VariableName_: "UNIQUE_ID",
			Variable_:     variables.UniqueID,
		},
	})
	if len(tx.matchedRules) == 0 || tx.matchedRules[0].Rule().ID() != rule.ID_ {
		t.Error("failed to match rule for audit")
	}
	al := tx.AuditLog()
	if len(al.Messages) == 0 || al.Messages[0].Data.ID != rule.ID_ {
		t.Error("failed to add rules to audit logs")
	}
	if al.Transaction.Request.Headers == nil || al.Transaction.Request.Headers["test"][0] != "test" {
		t.Error("failed to add request header to audit log")
	}
	if al.Transaction.Response.Headers == nil || al.Transaction.Response.Headers["test"][0] != "test" {
		t.Error("failed to add Response header to audit log")
	}
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func TestResetCapture(t *testing.T) {
	tx := makeTransaction(t)
	tx.Capture = true
	tx.CaptureField(5, "test")
	if tx.variables.tx.Get("5")[0] != "test" {
		t.Error("failed to set capture field from tx")
	}
	tx.resetCaptures()
	if tx.variables.tx.Get("5")[0] != "" {
		t.Error("failed to reset capture field from tx")
	}
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func TestRelevantAuditLogging(t *testing.T) {
	tx := makeTransaction(t)
	tx.WAF.AuditLogRelevantStatus = regexp.MustCompile(`(403)`)
	tx.variables.responseStatus.Set("403")
	tx.AuditEngine = types.AuditEngineRelevantOnly
	// tx.WAF.auditLogger = loggers.NewAuditLogger()
	tx.ProcessLogging()
	// TODO how do we check if the log was writen?
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func TestLogCallback(t *testing.T) {
	waf := NewWAF()
	buffer := ""
	waf.SetErrorLogCb(func(mr types.MatchedRule) {
		buffer = mr.ErrorLog(403)
	})
	tx := waf.NewTransaction()
	rule := NewRule()
	tx.MatchRule(rule, []types.MatchData{
		&corazarules.MatchData{
			VariableName_: "UNIQUE_ID",
			Variable_:     variables.UniqueID,
		},
	})
	if buffer == "" && strings.Contains(buffer, tx.id) {
		t.Error("failed to call error log callback")
	}
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func TestHeaderSetters(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.AddRequestHeader("cookie", "abc=def;hij=klm")
	tx.AddRequestHeader("test1", "test2")
	c := tx.variables.requestCookies.Get("abc")[0]
	if c != "def" {
		t.Errorf("failed to set cookie, got %q", c)
	}
	if tx.variables.requestHeaders.Get("cookie")[0] != "abc=def;hij=klm" {
		t.Error("failed to set request header")
	}
	if !utils.InSlice("cookie", tx.variables.requestHeadersNames.Get("cookie")) {
		t.Error("failed to set header name", tx.variables.requestHeadersNames.Get("cookie"))
	}
	if !utils.InSlice("abc", tx.variables.requestCookiesNames.Get("abc")) {
		t.Error("failed to set cookie name")
	}
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func TestRequestBodyProcessingAlgorithm(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.RuleEngine = types.RuleEngineOn
	tx.RequestBodyAccess = true
	tx.ForceRequestBodyVariable = true
	tx.AddRequestHeader("content-type", "text/plain")
	tx.AddRequestHeader("content-length", "7")
	if _, err := tx.RequestBodyBuffer.Write([]byte("test123")); err != nil {
		t.Error("Failed to write request body buffer")
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Error("failed to process request body")
	}
	if tx.variables.requestBody.String() != "test123" {
		t.Error("failed to set request body")
	}
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func TestTxVariables(t *testing.T) {
	tx := makeTransaction(t)
	rv := ruleVariableParams{
		Name:     "REQUEST_HEADERS",
		Variable: variables.RequestHeaders,
		KeyStr:   "ho.*",
		KeyRx:    regexp.MustCompile("ho.*"),
	}
	if len(tx.GetField(rv)) != 1 || tx.GetField(rv)[0].Value() != "www.test.com:80" {
		t.Errorf("failed to match rule variable REQUEST_HEADERS:host, %d matches, %v", len(tx.GetField(rv)), tx.GetField(rv))
	}
	rv.Count = true
	if len(tx.GetField(rv)) == 0 || tx.GetField(rv)[0].Value() != "1" {
		t.Errorf("failed to get count for regexp variable")
	}
	// now nil key
	rv.KeyRx = nil
	if len(tx.GetField(rv)) == 0 {
		t.Error("failed to match rule variable REQUEST_HEADERS with nil key")
	}
	rv.KeyStr = ""
	f := tx.GetField(rv)
	if len(f) == 0 {
		t.Error("failed to count variable REQUEST_HEADERS ")
	}
	count, err := strconv.Atoi(f[0].Value())
	if err != nil {
		t.Error(err)
	}
	if count != 5 {
		t.Errorf("failed to match rule variable REQUEST_HEADERS with count, %v", rv)
	}
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func TestTxVariablesExceptions(t *testing.T) {
	tx := makeTransaction(t)
	rv := ruleVariableParams{
		Name:     "REQUEST_HEADERS",
		Variable: variables.RequestHeaders,
		KeyStr:   "ho.*",
		KeyRx:    regexp.MustCompile("ho.*"),
		Exceptions: []ruleVariableException{
			{KeyStr: "host"},
		},
	}
	fields := tx.GetField(rv)
	if len(fields) != 0 {
		t.Errorf("REQUEST_HEADERS:host should not match, got %d matches, %v", len(fields), fields)
	}
	rv.Exceptions = nil
	fields = tx.GetField(rv)
	if len(fields) != 1 || fields[0].Value() != "www.test.com:80" {
		t.Errorf("failed to match rule variable REQUEST_HEADERS:host, %d matches, %v", len(fields), fields)
	}
	rv.Exceptions = []ruleVariableException{
		{
			KeyRx: regexp.MustCompile("ho.*"),
		},
	}
	fields = tx.GetField(rv)
	if len(fields) != 0 {
		t.Errorf("REQUEST_HEADERS:host should not match, got %d matches, %v", len(fields), fields)
	}
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func TestAuditLogMessages(t *testing.T) {

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
			t.Error(err)
		}
		tx = waf.NewTransaction()
		if len(tx.matchedRules) != 0 {
			t.Errorf("failed to sync transaction pool, %d rules found after %d attempts", len(tx.matchedRules), i+1)
			return
		}
	}
}

func TestTxPhase4Magic(t *testing.T) {
	waf := NewWAF()
	waf.ResponseBodyAccess = true
	waf.ResponseBodyLimit = 3
	tx := waf.NewTransaction()
	tx.AddResponseHeader("content-type", "text/html")
	if _, err := tx.ResponseBodyBuffer.Write([]byte("more bytes")); err != nil {
		t.Error(err)
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Error(err)
	}
	if tx.variables.outboundDataError.String() != "1" {
		t.Error("failed to set outbound data error")
	}
	if tx.variables.responseBody.String() != "mor" {
		t.Error("failed to set response body")
	}
}

func TestVariablesMatch(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.matchVariable(&corazarules.MatchData{
		VariableName_: "ARGS_NAMES",
		Variable_:     variables.ArgsNames,
		Key_:          "sample",
		Value_:        "samplevalue",
	})
	expect := map[variables.RuleVariable]string{
		variables.MatchedVar:     "samplevalue",
		variables.MatchedVarName: "ARGS_NAMES:sample",
	}

	for k, v := range expect {
		if m := (tx.Collection(k)).(*collection.Simple).String(); m != v {
			t.Errorf("failed to match variable %s, Expected: %s, got: %s", k.Name(), v, m)
		}
	}

	if len(tx.variables.matchedVars.Get("ARGS_NAMES:sample")) == 0 {
		t.Errorf("failed to match variable %s, got 0", variables.MatchedVars.Name())
	}
}

func TestTxReqBodyForce(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.RequestBodyAccess = true
	tx.ForceRequestBodyVariable = true
	if _, err := tx.RequestBodyBuffer.Write([]byte("test")); err != nil {
		t.Error(err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Error(err)
	}
	if tx.variables.requestBody.String() != "test" {
		t.Error("failed to set request body")
	}
}

func TestTxReqBodyForceNegative(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.RequestBodyAccess = true
	tx.ForceRequestBodyVariable = false
	if _, err := tx.RequestBodyBuffer.Write([]byte("test")); err != nil {
		t.Error(err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Error(err)
	}
	if tx.variables.requestBody.String() == "test" {
		t.Error("reqbody should not be there")
	}
}

func TestTxProcessConnection(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.ProcessConnection("127.0.0.1", 80, "127.0.0.2", 8080)
	if tx.variables.remoteAddr.String() != "127.0.0.1" {
		t.Error("failed to set client ip")
	}
	if tx.variables.remotePort.Int() != 80 {
		t.Error("failed to set client port")
	}
}

func TestTxAddArgument(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	tx.ProcessConnection("127.0.0.1", 80, "127.0.0.2", 8080)
	tx.AddArgument(types.ArgumentGET, "test", "testvalue")
	if tx.variables.argsGet.Get("test")[0] != "testvalue" {
		t.Error("failed to set args get")
	}
	tx.AddArgument(types.ArgumentPOST, "ptest", "ptestvalue")
	if tx.variables.argsPost.Get("ptest")[0] != "ptestvalue" {
		t.Error("failed to set args post")
	}
	tx.AddArgument(types.ArgumentPATH, "ptest2", "ptestvalue")
	if tx.variables.argsPath.Get("ptest2")[0] != "ptestvalue" {
		t.Error("failed to set args post")
	}
}

func TestTxGetField(t *testing.T) {
	tx := makeTransaction(t)
	rvp := ruleVariableParams{
		Name:     "args",
		Variable: variables.Args,
	}
	if f := tx.GetField(rvp); len(f) != 3 {
		t.Errorf("failed to get field, expected 2, got %d", len(f))
	}
}

func TestTxProcessURI(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	uri := "http://example.com/path/to/file.html?query=string&other=value"
	tx.ProcessURI(uri, "GET", "HTTP/1.1")
	if s := tx.variables.requestURI.String(); s != uri {
		t.Errorf("failed to set request uri, got %s", s)
	}
	if s := tx.variables.requestBasename.String(); s != "file.html" {
		t.Errorf("failed to set request path, got %s", s)
	}
	if tx.variables.queryString.String() != "query=string&other=value" {
		t.Error("failed to set request query")
	}
	if v := tx.variables.args.FindAll(); len(v) != 2 {
		t.Errorf("failed to set request args, got %d", len(v))
	}
	if v := tx.variables.args.FindString("other"); v[0].Value() != "value" {
		t.Errorf("failed to set request args, got %v", v)
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
			t.Error(err)
		}
		res := m.Expand(tx)
		if res != v {
			if testing.Verbose() {
				fmt.Println(tx.Debug())
				fmt.Println("===STACK===\n", string(debug.Stack())+"\n===STACK===")
			}
			t.Error("Failed set transaction for " + k + ", expected " + v + ", got " + res)
		}
	}
}

func TestMacro(t *testing.T) {
	tx := makeTransaction(t)
	tx.variables.tx.Set("some", []string{"secretly"})
	m, err := macro.NewMacro("%{unique_id}")
	if err != nil {
		t.Error(err)
	}
	if m.Expand(tx) != tx.id {
		t.Errorf("%s != %s", m.Expand(tx), tx.id)
	}
	m, err = macro.NewMacro("some complex text %{tx.some} wrapped in m")
	if err != nil {
		t.Error(err)
	}
	if m.Expand(tx) != "some complex text secretly wrapped in m" {
		t.Errorf("failed to expand m, got %s\n%v", m.Expand(tx), m)
	}

	_, err = macro.NewMacro("some complex text %{tx.some} wrapped in m %{tx.some}")
	if err != nil {
		t.Error(err)
		return
	}
	// TODO(anuraaga): Decouple this test from transaction implementation.
	// if !macro.IsExpandable() || len(macro.tokens) != 4 || macro.Expand(tx) != "some complex text secretly wrapped in m secretly" {
	//   t.Errorf("failed to parse replacements %v", macro.tokens)
	// }
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
