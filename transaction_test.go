// Copyright 2021 Juan Pablo Tosso
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

package coraza

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jptosso/coraza-waf/v2/types"
	"github.com/jptosso/coraza-waf/v2/types/variables"
	utils "github.com/jptosso/coraza-waf/v2/utils/strings"
)

var wafi = NewWaf()

func TestTxSetters(t *testing.T) {
	tx := makeTransaction()
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
	tx := wafi.NewTransaction()
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
		"%{files_combined_size}": "50",
		"%{files}":               "a.html",
		"%{files_names}":         "file1",
	}

	validateMacroExpansion(exp, tx, t)
}

func TestTxResponse(t *testing.T) {
	/*
		tx := wafi.NewTransaction()
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

func TestTxGetField(t *testing.T) {
	// GetField
}

func TestTxMatch(t *testing.T) {
	waf := NewWaf()
	r := NewRule()
	mr := MatchData{
		"test",
		0,
		"test",
		"test",
	}
	tx := waf.NewTransaction()
	tx.MatchRule(MatchedRule{
		Rule:        *r,
		MatchedData: mr,
	})
	if len(tx.MatchedRules) == 0 {
		t.Error("Failed to match value")
	}
}

func TestRequestBody(t *testing.T) {
	urlencoded := "some=result&second=data"
	// xml := "<test><content>test</content></test>"
	tx := wafi.NewTransaction()
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	if _, err := tx.RequestBodyBuffer.Write([]byte(urlencoded)); err != nil {
		t.Error("Failed to write body buffer")
	}
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Error("Failed to process request body")
	}
	val := tx.GetCollection(variables.ArgsPost).Get("some")
	if len(val) != 1 || val[0] != "result" {
		t.Error("Failed to set url encoded post data")
	}
}

func TestResponseHeader(t *testing.T) {
	tx := makeTransaction()
	tx.AddResponseHeader("content-type", "test")
	if tx.GetCollection(variables.ResponseContentType).GetFirstString("") != "test" {
		t.Error("invalid RESPONSE_CONTENT_TYPE after response headers")
	}
}

func TestAuditLog(t *testing.T) {
	tx := makeTransaction()
	tx.AuditLogParts = []rune("ABCDEFGHIJK")
	al := tx.AuditLog()
	if al.Transaction.ID != tx.ID {
		t.Error("invalid auditlog id")
	}
	// TODO more checks
}

func TestResponseBody(t *testing.T) {
	tx := makeTransaction()
	tx.ResponseBodyAccess = true
	tx.RuleEngine = types.RuleEngineOn
	tx.AddResponseHeader("content-type", "text/plain")
	if _, err := tx.ResponseBodyBuffer.Write([]byte("test123")); err != nil {
		t.Error("Failed to write response body buffer")
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Error("Failed to process response body")
	}
	if tx.GetCollection(variables.ResponseBody).GetFirstString("") != "test123" {
		t.Error("failed to set response body")
	}
}

func TestAuditLogFields(t *testing.T) {
	tx := makeTransaction()
	tx.AuditLogParts = []rune("ABCDEFGHIJK")
	tx.AddRequestHeader("test", "test")
	tx.AddResponseHeader("test", "test")
	rule := NewRule()
	rule.ID = 131
	tx.MatchRule(MatchedRule{
		Rule:    *rule,
		Message: "some msg",
		ID:      tx.ID,
		MatchedData: MatchData{
			VariableName: "UNIQUE_ID",
			Variable:     variables.UniqueID,
		},
	})
	if len(tx.MatchedRules) == 0 || tx.MatchedRules[0].Rule.ID != rule.ID {
		t.Error("failed to match rule for audit")
	}
	al := tx.AuditLog()
	if len(al.Messages) == 0 || al.Messages[0].Data.ID != rule.ID {
		t.Error("failed to add rules to audit logs")
	}
	if al.Transaction.Request.Headers == nil || al.Transaction.Request.Headers["test"][0] != "test" {
		t.Error("failed to add request header to audit log")
	}
	if al.Transaction.Response.Headers == nil || al.Transaction.Response.Headers["test"][0] != "test" {
		t.Error("failed to add Response header to audit log")
	}
}

func TestRequestStruct(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://www.coraza.io/test", strings.NewReader("test=456"))
	waf := NewWaf()
	tx := waf.NewTransaction()
	if _, err := tx.ProcessRequest(req); err != nil {
		t.Error(err)
	}
	if tx.GetCollection(variables.RequestMethod).GetFirstString("") != "POST" {
		t.Error("failed to set request from request object")
	}
}

func TestResetCapture(t *testing.T) {
	tx := makeTransaction()
	tx.CaptureField(5, "test")
	if tx.GetCollection(variables.TX).GetFirstString("5") != "test" {
		t.Error("failed to set capture field from tx")
	}
	tx.resetAfterRule()
	if tx.GetCollection(variables.TX).GetFirstString("5") != "" {
		t.Error("failed to reset capture field from tx")
	}
}

func TestRelevantAuditLogging(t *testing.T) {
	tx := makeTransaction()
	tx.Waf.AuditLogRelevantStatus = regexp.MustCompile(`(403)`)
	tx.GetCollection(variables.ResponseStatus).Set("", []string{"403"})
	tx.AuditEngine = types.AuditEngineRelevantOnly
	tx.Log = false
	// tx.Waf.auditLogger = loggers.NewAuditLogger()
	tx.ProcessLogging()
	// TODO how do we check if the log was writen?
}

func TestLogCallback(t *testing.T) {
	waf := NewWaf()
	buffer := ""
	waf.errorLogCb = func(mr MatchedRule) {
		buffer = mr.ErrorLog(403)
	}
	tx := waf.NewTransaction()
	tx.MatchRule(MatchedRule{
		Rule: *NewRule(),
		MatchedData: MatchData{
			VariableName: "UNIQUE_ID",
			Variable:     variables.UniqueID,
		},
	})
	if buffer == "" && strings.Contains(buffer, tx.ID) {
		t.Error("failed to call error log callback")
	}
}

func TestHeaderSetters(t *testing.T) {
	waf := NewWaf()
	tx := waf.NewTransaction()
	tx.AddRequestHeader("cookie", "abc=def;hij=klm")
	tx.AddRequestHeader("test1", "test2")
	c := tx.GetCollection(variables.RequestCookies).GetFirstString("abc")
	if c != "def" {
		t.Errorf("failed to set cookie, got %q", c)
	}
	if tx.GetCollection(variables.RequestHeaders).GetFirstString("cookie") != "abc=def;hij=klm" {
		t.Error("failed to set request header")
	}
	if !utils.InSlice("cookie", tx.GetCollection(variables.RequestHeadersNames).Get("")) {
		t.Error("failed to set header name")
	}
	if !utils.InSlice("abc", tx.GetCollection(variables.RequestCookiesNames).Get("")) {
		t.Error("failed to set cookie name")
	}
}

func TestRequestBodyProcessingAlgorithm(t *testing.T) {
	waf := NewWaf()
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
	if tx.GetCollection(variables.RequestBody).GetFirstString("") != "test123" {
		t.Error("failed to set request body")
	}
}

func TestTxVariables(t *testing.T) {
	tx := makeTransaction()
	rv := ruleVariableParams{
		Name:     "REQUEST_HEADERS",
		Variable: variables.RequestHeaders,
		KeyStr:   "ho.*",
		KeyRx:    regexp.MustCompile("ho.*"),
	}
	if len(tx.GetField(rv)) != 1 || tx.GetField(rv)[0].Value != "www.test.com:80" {
		t.Errorf("failed to match rule variable REQUEST_HEADERS:host, %d matches, %v", len(tx.GetField(rv)), tx.GetField(rv))
	}
	rv.Count = true
	if len(tx.GetField(rv)) == 0 || tx.GetField(rv)[0].Value != "1" {
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
	count, err := strconv.Atoi(f[0].Value)
	if err != nil {
		t.Error(err)
	}
	if count != 5 {
		t.Errorf("failed to match rule variable REQUEST_HEADERS with count, %v", rv)
	}
}

func TestTxVariablesExceptions(t *testing.T) {
	tx := makeTransaction()
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
	rv.Exceptions = []ruleVariableException{}
	fields = tx.GetField(rv)
	if len(fields) != 1 || fields[0].Value != "www.test.com:80" {
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
}

func BenchmarkTransactionCreation(b *testing.B) {
	waf := NewWaf()
	for i := 0; i < b.N; i++ {
		waf.NewTransaction()
	}
}

func makeTransaction() *Transaction {
	tx := wafi.NewTransaction()
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
	_, _ = tx.ParseRequestReader(strings.NewReader(data))
	return tx
}

func validateMacroExpansion(tests map[string]string, tx *Transaction, t *testing.T) {
	for k, v := range tests {
		res := tx.MacroExpansion(k)
		if res != v {
			t.Error("Failed set transaction for " + k + ", expected " + v + ", got " + res)
		}
	}
}
