// Copyright 2022 Juan Pablo Tosso
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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v2/types"
	"github.com/corazawaf/coraza/v2/types/variables"
	utils "github.com/corazawaf/coraza/v2/utils/strings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var wafi = NewWaf()

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

	validateMacroExpansion(t, exp, tx)
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
	require.NoError(t, err, "Failed to parse multipart request")
	exp := map[string]string{
		"%{args_post.text}":      "test-value",
		"%{files_combined_size}": "60",
		"%{files}":               "a.html",
		"%{files_names}":         "file1",
	}

	validateMacroExpansion(t, exp, tx)
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

func TestRequestBody(t *testing.T) {
	urlencoded := "some=result&second=data"
	// xml := "<test><content>test</content></test>"
	tx := wafi.NewTransaction()
	tx.RequestBodyAccess = true
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	_, err := tx.RequestBodyBuffer.Write([]byte(urlencoded))
	require.NoError(t, err, "Failed to write body buffer")

	tx.ProcessRequestHeaders()
	_, err = tx.ProcessRequestBody()
	require.NoError(t, err, "Failed to process request body")

	val := tx.GetCollection(variables.ArgsPost).Get("some")
	require.Len(t, val, 1)
	assert.Equal(t, "result", val[0], "Failed to set url encoded post data")
}

func TestResponseHeader(t *testing.T) {
	tx := makeTransaction(t)
	tx.AddResponseHeader("content-type", "test")
	require.Equal(
		t,
		"test",
		tx.GetCollection(variables.ResponseContentType).GetFirstString(""),
		"invalid RESPONSE_CONTENT_TYPE after response headers",
	)
}

func TestAuditLog(t *testing.T) {
	tx := makeTransaction(t)
	tx.AuditLogParts = types.AuditLogParts("ABCDEFGHIJK")

	al := tx.AuditLog()
	require.Equal(t, tx.ID, al.Transaction.ID, "invalid auditlog id")

	// TODO more checks
	require.NoError(t, tx.Clean())
}

func TestResponseBody(t *testing.T) {
	tx := makeTransaction(t)
	tx.ResponseBodyAccess = true
	tx.RuleEngine = types.RuleEngineOn
	tx.AddResponseHeader("content-type", "text/plain")
	_, err := tx.ResponseBodyBuffer.Write([]byte("test123"))
	require.NoError(t, err, "Failed to write response body buffer")

	_, err = tx.ProcessResponseBody()
	require.NoError(t, err, "Failed to process response body")
	require.Equal(t, "test123", tx.GetCollection(variables.ResponseBody).GetFirstString(""), "failed to set response body")

	require.NoError(t, tx.Clean())
}

func TestAuditLogFields(t *testing.T) {
	tx := makeTransaction(t)
	tx.AuditLogParts = types.AuditLogParts("ABCDEFGHIJK")
	tx.AddRequestHeader("test", "test")
	tx.AddResponseHeader("test", "test")
	rule := NewRule()
	rule.ID = 131
	tx.MatchRule(rule, []MatchData{
		{
			VariableName: "UNIQUE_ID",
			Variable:     variables.UniqueID,
		},
	})

	require.True(t, len(tx.MatchedRules) > 0)
	require.Equal(t, rule.ID, tx.MatchedRules[0].Rule.ID, "failed to match rule for audit")

	al := tx.AuditLog()
	require.True(t, len(al.Messages) > 0)
	assert.Equal(t, rule.ID, al.Messages[0].Data.ID, "failed to add rules to audit logs")

	require.NotNil(t, al.Transaction.Request.Headers)
	assert.Equal(t, "test", al.Transaction.Request.Headers["test"][0], "failed to add request header to audit log")

	require.NotNil(t, al.Transaction.Response.Headers)
	assert.Equal(t, "test", al.Transaction.Response.Headers["test"][0], "failed to add request header to audit log")

	require.NoError(t, tx.Clean())
}

func TestRequestStruct(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://www.coraza.io/test", strings.NewReader("test=456"))
	waf := NewWaf()
	tx := waf.NewTransaction()

	_, err := tx.ProcessRequest(req)
	require.NoError(t, err)
	require.Equal(t, "POST", tx.GetCollection(variables.RequestMethod).GetFirstString(""), "failed to set request from request object")
	require.NoError(t, tx.Clean())
}

func TestResetCapture(t *testing.T) {
	tx := makeTransaction(t)
	tx.Capture = true
	tx.CaptureField(5, "test")

	require.Equal(t, "test", tx.GetCollection(variables.TX).GetFirstString("5"), "failed to set capture field from tx")

	tx.resetCaptures()
	require.Equal(t, "", tx.GetCollection(variables.TX).GetFirstString("5"), "failed to reset capture field from tx")
	require.NoError(t, tx.Clean())
}

func TestRelevantAuditLogging(t *testing.T) {
	tx := makeTransaction(t)
	tx.Waf.AuditLogRelevantStatus = regexp.MustCompile(`(403)`)
	tx.GetCollection(variables.ResponseStatus).Set("", []string{"403"})
	tx.AuditEngine = types.AuditEngineRelevantOnly
	// tx.Waf.auditLogger = loggers.NewAuditLogger()
	tx.ProcessLogging()
	// TODO how do we check if the log was writen?
	require.NoError(t, tx.Clean())
}

func TestLogCallback(t *testing.T) {
	waf := NewWaf()
	buffer := ""
	waf.errorLogCb = func(mr MatchedRule) {
		buffer = mr.ErrorLog(403)
	}
	tx := waf.NewTransaction()
	rule := NewRule()
	tx.MatchRule(rule, []MatchData{
		{
			VariableName: "UNIQUE_ID",
			Variable:     variables.UniqueID,
		},
	})
	require.Empty(t, buffer)
	// require.NotEmpty(t, buffer)
	// require.Contains(t, buffer, tx.ID, "failed to call error log callback")
	require.NoError(t, tx.Clean())
}

func TestHeaderSetters(t *testing.T) {
	waf := NewWaf()
	tx := waf.NewTransaction()
	tx.AddRequestHeader("cookie", "abc=def;hij=klm")
	tx.AddRequestHeader("test1", "test2")
	c := tx.GetCollection(variables.RequestCookies).GetFirstString("abc")
	require.Equal(t, "def", c, "failed to set cookie")
	require.Equal(t, "abc=def;hij=klm", tx.GetCollection(variables.RequestHeaders).GetFirstString("cookie"), "failed to set request header")
	require.True(t, utils.InSlice("cookie", tx.GetCollection(variables.RequestHeadersNames).Get("cookie")), "failed to set header name")
	require.True(t, utils.InSlice("abc", tx.GetCollection(variables.RequestCookiesNames).Get("abc")), "failed to set cookie name")
	require.NoError(t, tx.Clean())
}

func TestRequestBodyProcessingAlgorithm(t *testing.T) {
	waf := NewWaf()
	tx := waf.NewTransaction()
	tx.RuleEngine = types.RuleEngineOn
	tx.RequestBodyAccess = true
	tx.ForceRequestBodyVariable = true
	tx.AddRequestHeader("content-type", "text/plain")
	tx.AddRequestHeader("content-length", "7")

	_, err := tx.RequestBodyBuffer.Write([]byte("test123"))
	require.NoError(t, err, "Failed to write request body buffer")

	_, err = tx.ProcessRequestBody()
	require.NoError(t, err, "failed to process request body")

	require.Equal(t, "test123", tx.GetCollection(variables.RequestBody).GetFirstString(""), "failed to set request body")
	require.NoError(t, tx.Clean())
}

func TestTxVariables(t *testing.T) {
	tx := makeTransaction(t)
	rv := ruleVariableParams{
		Name:     "REQUEST_HEADERS",
		Variable: variables.RequestHeaders,
		KeyStr:   "ho.*",
		KeyRx:    regexp.MustCompile("ho.*"),
	}

	rvField := tx.GetField(rv)
	require.Len(t, rvField, 1, "failed to match rule variable REQUEST_HEADERS:host")
	require.Equal(t, "www.test.com:80", rvField[0].Value, "failed to match rule variable REQUEST_HEADERS:host")

	rv.Count = true
	rvField = tx.GetField(rv)
	require.True(t, len(rvField) > 0, "failed to get count for regexp variable")
	require.Equal(t, rvField[0].Value, "1", "failed to get count for regexp variable")

	// now nil key
	rv.KeyRx = nil
	require.True(t, len(rvField) > 0, "failed to match rule variable REQUEST_HEADERS with nil key")

	rv.KeyStr = ""
	rvField = tx.GetField(rv)
	require.True(t, len(rvField) > 0, "failed to count variable REQUEST_HEADERS")

	count, err := strconv.Atoi(rvField[0].Value)
	require.NoError(t, err)

	if count != 5 {
		t.Errorf("failed to match rule variable REQUEST_HEADERS with count, %v", rv)
	}
	require.NoError(t, tx.Clean())
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
	require.NoError(t, tx.Clean())
}

func TestAuditLogMessages(t *testing.T) {

}

func TestProcessRequestMultipart(t *testing.T) {
	req, _ := http.NewRequest("POST", "/some", nil)
	err := multipartRequest(t, req)
	require.NoError(t, err)

	tx := makeTransaction(t)
	tx.RequestBodyAccess = true

	_, err = tx.ProcessRequest(req)
	require.NoError(t, err)

	require.NotNil(t, req.Body, "failed to process multipart request")

	reader := bufio.NewReader(req.Body)
	_, err = reader.ReadString('\n')
	require.NoError(t, err, "failed to read multipart request")
	require.NoError(t, tx.Clean())
}

func TestTransactionSyncPool(t *testing.T) {
	waf := NewWaf()
	tx := waf.NewTransaction()
	tx.MatchedRules = append(tx.MatchedRules, MatchedRule{Rule: &Rule{ID: 1234}})
	for i := 0; i < 1000; i++ {
		assert.NoError(t, tx.Clean())
		tx = waf.NewTransaction()
		require.Lenf(t, tx.MatchedRules, 0, "failed to sync transaction pool, %d rules found after %d attempts", len(tx.MatchedRules), i+1)
	}
}

func TestTxPhase4Magic(t *testing.T) {
	waf := NewWaf()
	tx := waf.NewTransaction()
	tx.AddResponseHeader("content-type", "text/html")
	tx.ResponseBodyAccess = true
	tx.Waf.ResponseBodyLimit = 3
	if _, err := tx.ResponseBodyBuffer.Write([]byte("more bytes")); err != nil {
		t.Error(err)
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Error(err)
	}
	if tx.GetCollection(variables.OutboundDataError).GetFirstString("") != "1" {
		t.Error("failed to set outbound data error")
	}
	if tx.GetCollection(variables.ResponseBody).GetFirstString("") != "mor" {
		t.Error("failed to set response body")
	}
}

func TestVariablesMatch(t *testing.T) {
	waf := NewWaf()
	tx := waf.NewTransaction()
	tx.matchVariable(&MatchData{
		VariableName: "ARGS_NAMES",
		Variable:     variables.ArgsNames,
		Key:          "sample",
		Value:        "samplevalue",
	})
	expect := map[variables.RuleVariable]string{
		variables.MatchedVar:     "samplevalue",
		variables.MatchedVarName: "ARGS_NAMES:sample",
	}

	for k, v := range expect {
		assert.Equalf(t, v, tx.GetCollection(k).GetFirstString(""), "failed to match variable %s", k.Name())
	}

	assert.Equalf(t, "samplevalue", tx.GetCollection(variables.MatchedVars).GetFirstString("ARGS_NAMES:sample"), "failed to match variable")
}

func TestTxReqBodyForce(t *testing.T) {
	waf := NewWaf()
	tx := waf.NewTransaction()
	tx.RequestBodyAccess = true
	tx.ForceRequestBodyVariable = true
	_, err := tx.RequestBodyBuffer.Write([]byte("test"))
	require.NoError(t, err)

	_, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.Equal(t, "test", tx.GetCollection(variables.RequestBody).GetFirstString(""), "failed to set request body")
}

func TestTxReqBodyForceNegative(t *testing.T) {
	waf := NewWaf()
	tx := waf.NewTransaction()
	tx.RequestBodyAccess = true
	tx.ForceRequestBodyVariable = false

	_, err := tx.RequestBodyBuffer.Write([]byte("test"))
	require.NoError(t, err)

	_, err = tx.ProcessRequestBody()
	require.NoError(t, err)

	require.NotEqual(t, "test", tx.GetCollection(variables.RequestBody).GetFirstString(""), "reqbody should not be there")
}

const SIZE_5MB = 1024 * 5

func multipartRequest(t *testing.T, req *http.Request) error {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	tempfile, err := os.CreateTemp("/tmp", "tmpfile*")
	if err != nil {
		return err
	}
	defer os.Remove(tempfile.Name())
	for i := 0; i < SIZE_5MB; i++ {
		if _, err := tempfile.Write([]byte(strings.Repeat("A", 1024))); err != nil {
			return err
		}
	}
	var fw io.Writer
	if fw, err = w.CreateFormFile("fupload", tempfile.Name()); err != nil {
		return err
	}
	if _, err := tempfile.Seek(0, 0); err != nil {
		return err
	}
	if _, err = io.Copy(fw, tempfile); err != nil {
		return err
	}
	req.Body = ioutil.NopCloser(&b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Method = "POST"
	return nil
}

func BenchmarkTransactionCreation(b *testing.B) {
	waf := NewWaf()
	for i := 0; i < b.N; i++ {
		waf.NewTransaction()
	}
}

func BenchmarkNewTxWithoutPool(b *testing.B) {
	var p *Transaction
	waf := NewWaf()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 10000; j++ {
			p = new(Transaction)
			p.Waf = waf
		}
	}
}

/*
Commented because go-critic hates it.
func BenchmarkNewTxWithPool(b *testing.B) {
	var p *Transaction
	b.ReportAllocs()
	b.ResetTimer()
	waf := NewWaf()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 10000; j++ {
			p = transactionPool.Get().(*Transaction)
			p.Waf = waf
			transactionPool.Put(p)
		}
	}
}*/

func makeTransaction(t *testing.T) *Transaction {
	t.Helper()
	tx := wafi.NewTransaction()
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
	require.NoError(t, err)
	return tx
}

func validateMacroExpansion(t *testing.T, tests map[string]string, tx *Transaction) {
	t.Helper()
	for k, v := range tests {
		macro, err := NewMacro(k)
		assert.NoError(t, err)
		res := macro.Expand(tx)
		assert.Equalf(t, v, res, "failed set transaction for %q\n\n%s", k, string(debug.Stack()))
	}
}
