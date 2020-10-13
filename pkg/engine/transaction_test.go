// Copyright 2020 Juan Pablo Tosso
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

package engine

import (
	"net/url"
	"strings"
	"testing"
)

var wafi = NewWaf()

func TestTxSetters(t *testing.T) {
	tx := makeTransaction()
	exp := map[string]string{
		//TODO somehow host is being overriden
		//"%{request_headers.host}": "www.test.com:80",
		"%{request_headers.x-test-header}": "test456",
		"%{request_method}":                "POST",
		"%{ARGS_GET.id}":                   "123",
		"%{request_cookies.test}":          "123",
		"%{args_post.testfield}":           "456",
		"%{args.testfield}":                "456",
		"%{request_line}":                  "POST /testurl.php?id=123&b=456 HTTP/1.1",
		"%{query_string}":                  "id=123&b=456",
		"%{request_body_length}":           "13",
		"%{request_filename}":              "/testurl.php",
		"%{request_protocol}":              "HTTP/1.1",
		"%{request_uri}":                   "/testurl.php?id=123&b=456",
		"%{request_uri_raw}":               "/testurl.php?id=123&b=456",
		"%{id}":                            tx.Id,
	}

	validateMacroExpansion(exp, tx, t)
}

func TestTxMultipart(t *testing.T) {
	tx := wafi.NewTransaction()
	ht := []string{
		"POST / HTTP/1.1",
		"Host: localhost:8000",
		"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:29.0) Gecko/20100101 Firefox/29.0",
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language: en-US,en;q=0.5",
		"Accept-Encoding: gzip, deflate",
		"Connection: keep-alive",
		"Content-Type: multipart/form-data; boundary=---------------------------9051914041544843365972754266",
		"Content-Length: 552",
		"",
		"-----------------------------9051914041544843365972754266",
		"Content-Disposition: form-data; name=\"text\"",
		"",
		"test-value",
		"-----------------------------9051914041544843365972754266",
		"Content-Disposition: form-data; name=\"file1\"; filename=\"a.txt\"",
		"Content-Type: text/plain",
		"",
		"Content of a.txt.",
		"",
		"-----------------------------9051914041544843365972754266",
		"Content-Disposition: form-data; name=\"file2\"; filename=\"a.html\"",
		"Content-Type: text/html",
		"",
		"<!DOCTYPE html><title>Content of a.html.</title>",
		"",
		"-----------------------------9051914041544843365972754266--",
	}
	data := strings.Join(ht, "\r\n")
	tx.ParseRequestString(data)
	exp := map[string]string{
		"%{args_post.text}":      "test-value",
		"%{files_combined_size}": "69",
	}

	validateMacroExpansion(exp, tx, t)

	//TODO check files
}

func TestTxResponse(t *testing.T) {
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
		"%{response_headers.server}": "Microsoft-IIS/8.5",
	}

	validateMacroExpansion(exp, tx, t)
}

func TestTxSetters2(t *testing.T) {
	tx := wafi.NewTransaction()
	tx.RequestBodyAccess = true
	tx.ResponseBodyAccess = true
	tx.AddRequestHeader("testheader", "testvalue")
	tx.AddRequestHeader("testheader2", "testvalue2")
	tx.SetRemoteUser("testuser")
	tx.SetRequestBody("asdf", 4, "application/xml")
	tx.SetRequestBody("asdf", 4, "application/json")
	tx.SetResponseBody("test", 4)
	tx.SetResponseHeaders(map[string][]string{
		"test": []string{"testvalue"},
	})
	tx.SetResponseStatus(200)
	uri, _ := url.Parse("?id=123&name=456&test=789")
	tx.AddGetArgsFromUrl(uri)
	tx.AddPostArgsFromUrl(uri)
	tx.SetRequestMethod("GET")
	tx.SetRemoteAddress("1.1.1.1", 1234)
	tx.ResolveRemoteHost()
	tx.CaptureField(1, "test")
	if tx.GetCollection("tx").Get("1")[0] != "test" {
		t.Error("Failed to set capture")
	}
	tx.ResetCapture()
	if tx.GetCollection("tx").Get("1")[0] != "" {
		t.Error("Failed to reset capture groups")
	}
	//MatchRule
	tx.GetStopWatch()
	if tx.GetCollections() == nil {
		t.Error("Failed to initialize TX collections")
	}
	//GetRemovedTargets()
	//IsRelevantStatus()
	if tx.GetErrorPage() == "" {
		t.Error("Failed to render error page")
	}


	tx.RemoveRuleTargetById(1, "col", "key")
	if len(tx.RuleRemoveTargetById) == 0 || len(tx.RuleRemoveTargetById[1]) == 0{
		t.Error("Failed to remove rule target by id")
	}else{
		ctl := tx.RuleRemoveTargetById[1][0]
		if ctl.Name != "col" || ctl.Key != "key" {
			t.Error("Failed to create rule remove target by id")
		}
	}

	pc := &PersistentCollection{}
	//pc.Init("test")
	tx.RegisterPersistentCollection("test", pc)
	if tx.PersistentCollections["test"] == nil {
		t.Error("Failed to initialize persistent collection")
	}

	tx.SetCapturable(false)
	if tx.IsCapturable() {
		t.Error("Failed to set capturable")
	}
	tx.SetFullRequest()
	if tx.GetCollection("full_request").GetFirstString() == "" {
		t.Error("Failed to set full_request")
	}

	exp := map[string]string{
		"%{remote_user}":                 "testuser",
		"%{args_post.name}":              "456",
		"%{args_get.name}":               "456",
		"%{args.name}":                   "456",
		"%{remote_host}":                 "one.one.one.one.",
		"%{request_headers.testheader}":  "testvalue",
		"%{request_headers.testheader2}": "testvalue2",
		"%{response_headers.test}":       "testvalue",
	}

	validateMacroExpansion(exp, tx, t)
}

func TestTxGetField(t *testing.T) {
	//GetField
}

func TestTxPhases(t *testing.T) {
	tx := wafi.NewTransaction()
	tx.ExecutePhase(1)
	if tx.LastPhase != 1 {
		t.Error("Failed to execute phase")
	}
	tx.Disrupted = true
	tx.ExecutePhase(2)
	if tx.LastPhase != 1 {
		t.Error("Phase 2 should be stopped")
	}
	tx.Disrupted = false
	tx.ExecutePhase(5)
	if tx.LastPhase != 5 {
		t.Error("Failed to execute phase 5")
	}
}

func TestErrorPage(t *testing.T) {
	tx := makeTransaction()
	tx.WafInstance.ErrorPageMethod = ERROR_PAGE_SCRIPT
	tx.WafInstance.ErrorPageFile = "../../examples/scripts/error.sh"
	if tx.GetErrorPage() == "Error script failed" {
		t.Error("Failed to execute test error script")
	}
	tx.WafInstance.ErrorPageFile = "../../"
	if tx.GetErrorPage() != "Error script failed" {
		t.Error("This error script shouldnt be working")
	}	
}

func TestTxMatch(t *testing.T) {
	waf := NewWaf()
	r := NewRule()
	mr := []*MatchData{
		&MatchData{
			"test",
			"test",
			"test",
		},
	}
	tx := waf.NewTransaction()
	tx.MatchRule(r, []string{"msg"}, mr)
	if len(tx.MatchedRules) == 0 {
		t.Error("Failed to match value")
	}
}

func makeTransaction() *Transaction{
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
	tx.ParseRequestString(data)
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
