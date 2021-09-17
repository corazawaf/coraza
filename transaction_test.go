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
	"strings"
	"testing"
)

var wafi = NewWaf()

func TestGetCollections(t *testing.T) {
	//this test is just dumb
	tx := wafi.NewTransaction()
	tx.GetCollections()
}

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

func TestTxSetters2(t *testing.T) {
	//TODO must be rebuilt
}

func TestTxGetField(t *testing.T) {
	//GetField
}

func TestTxMatch(t *testing.T) {
	waf := NewWaf()
	r := NewRule()
	mr := []MatchData{
		{
			"test",
			"test",
			"test",
		},
	}
	tx := waf.NewTransaction()
	tx.MatchRule(*r, []string{"msg"}, mr)
	if len(tx.MatchedRules) == 0 {
		t.Error("Failed to match value")
	}
}

func TestRequestBody(t *testing.T) {
	urlencoded := "some=result&second=data"
	//xml := "<test><content>test</content></test>"
	tx := wafi.NewTransaction()
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	tx.RequestBodyBuffer.Write([]byte(urlencoded))
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()
	val := tx.GetCollection(VARIABLE_ARGS_POST).Get("some")
	if len(val) != 1 || val[0] != "result" {
		t.Error("Failed to set url encoded post data")
	}
}

func TestFullRequest(t *testing.T) {
	tx := makeTransaction()
	tx.SetFullRequest()
	data := tx.GetCollection(VARIABLE_FULL_REQUEST).GetFirstString("")
	if len(data) == 0 {
		t.Error("invalid FULL_REQUEST length")
	}
}

func TestResponseHeader(t *testing.T) {
	tx := makeTransaction()
	tx.AddResponseHeader("content-type", "test")
	if tx.GetCollection(VARIABLE_RESPONSE_CONTENT_TYPE).GetFirstString("") != "test" {
		t.Error("invalid RESPONSE_CONTENT_TYPE after response headers")
	}
}

func TestAuditLog(t *testing.T) {
	tx := makeTransaction()
	tx.AuditLogParts = []rune("ABCDEFGHIJK")
	al := tx.AuditLog()
	if al.Transaction.Id != tx.Id {
		t.Error("invalid auditlog id")
	}
	//TODO more checks
}

func TestResponseBody(t *testing.T) {
	tx := makeTransaction()
	tx.ResponseBodyAccess = true
	tx.RuleEngine = RULE_ENGINE_ON
	tx.AddResponseHeader("content-type", "text/plain")
	tx.ResponseBodyBuffer.Write([]byte("test123"))
	tx.ProcessResponseBody()
	if tx.GetCollection(VARIABLE_RESPONSE_BODY).GetFirstString("") != "test123" {
		t.Error("failed to set response body")
	}
}

func TestAuditLogFields(t *testing.T) {
	tx := makeTransaction()
	tx.AuditLogParts = []rune("ABCDEFGHIJK")
	tx.AddRequestHeader("test", "test")
	tx.AddResponseHeader("test", "test")
	rule := NewRule()
	rule.Id = 131
	tx.MatchRule(*rule, []string{"some msg"}, []MatchData{{"UNIQUE_ID", "", tx.Id}})
	if len(tx.MatchedRules) == 0 || tx.MatchedRules[0].Rule.Id != rule.Id {
		t.Error("failed to match rule for audit")
	}
	al := tx.AuditLog()
	if len(al.Messages) == 0 || al.Messages[0].Data.Id != rule.Id {
		t.Error("failed to add rules to audit logs")
	}
	if al.Transaction.Request.Headers == nil || al.Transaction.Request.Headers["test"][0] != "test" {
		t.Error("failed to add request header to audit log")
	}
	if al.Transaction.Response.Headers == nil || al.Transaction.Response.Headers["test"][0] != "test" {
		t.Error("failed to add Response header to audit log")
	}
}

type testel struct {
	Output string
}

func (te *testel) Emergency(msg string) {
	te.Output = msg
}
func (te *testel) Alert(msg string) {
	te.Output = msg
}
func (te *testel) Critical(msg string) {
	te.Output = msg
}
func (te *testel) Error(msg string) {
	te.Output = msg
}
func (te *testel) Warning(msg string) {
	te.Output = msg
}
func (te *testel) Notice(msg string) {
	te.Output = msg
}
func (te *testel) Info(msg string) {
	te.Output = msg
}
func (te *testel) Debug(msg string) {
	te.Output = msg
}

var _ EventLogger = &testel{}

func TestErrorLog(t *testing.T) {
	tx := makeTransaction()
	el := &testel{}
	tx.Waf.ErrorLogger = el
	rule := NewRule()
	rule.Id = 15
	rule.Msg = "test"
	rule.Log = true
	tx.MatchRule(*rule, []string{"messages"}, []MatchData{{
		Collection: "test",
	}})
	if !strings.Contains(el.Output, `[id "15"]`) {
		t.Error("failed to create error log with severity")
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
	tx.ParseRequestReader(strings.NewReader(data))
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
