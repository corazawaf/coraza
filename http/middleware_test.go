// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package http

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/seclang"
	"github.com/corazawaf/coraza/v3/types"
)

func TestProcessRequest(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://www.coraza.io/test", strings.NewReader("test=456"))
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	tx := waf.NewTransaction().(*corazawaf.Transaction)
	if _, err := processRequest(tx, req); err != nil {
		t.Fatal(err)
	}
	if tx.Variables().RequestMethod().Get() != "POST" {
		t.Fatal("failed to set request from request object")
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProcessRequestEngineOff(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://www.coraza.io/test", strings.NewReader("test=456"))
	// TODO(jcchavezs): Shall we make RuleEngine a first class method in WAF config?
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine OFF"))
	tx := waf.NewTransaction().(*corazawaf.Transaction)
	if _, err := processRequest(tx, req); err != nil {
		t.Fatal(err)
	}
	if tx.Variables().RequestMethod().Get() != "POST" {
		t.Fatal("failed to set request from request object")
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProcessRequestMultipart(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig().WithRequestBodyAccess())

	tx := waf.NewTransaction()

	req := createMultipartRequest(t)

	if _, err := processRequest(tx, req); err != nil {
		t.Fatal(err)
	}

	if req.Body == nil {
		t.Error("failed to process multipart request: nil body")
	}
	defer req.Body.Close()

	reader := bufio.NewReader(req.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Errorf("failed to read multipart request: %s", err.Error())
	}

	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProcessRequestTransferEncodingChunked(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
SecRule &REQUEST_HEADERS:Transfer-Encoding "!@eq 0" "id:1,phase:1,deny"
`))
	tx := waf.NewTransaction()

	req, _ := http.NewRequest("GET", "https://www.coraza.io/test", nil)
	req.TransferEncoding = []string{"chunked"}

	it, err := processRequest(tx, req)
	if err != nil {
		t.Fatal(err)
	}
	if it == nil {
		t.Fatal("Expected interruption")
	} else if it.RuleID != 1 {
		t.Fatalf("Expected rule 1 to be triggered, got rule %d", it.RuleID)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
}

func createMultipartRequest(t *testing.T) *http.Request {
	t.Helper()

	metadata := `{"name": "photo-sample.jpeg"}`
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	metadataHeader := textproto.MIMEHeader{}
	metadataHeader.Set("Content-Type", "application/json; charset=UTF-8")

	part, err := writer.CreatePart(metadataHeader)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte(metadata))

	mediaHeader := textproto.MIMEHeader{}
	mediaHeader.Set("Content-Type", "image/jpeg")

	mediaPart, err := writer.CreatePart(mediaHeader)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(mediaPart, bytes.NewReader([]byte{255, 1, 2}))

	writer.Close()

	req, err := http.NewRequest("POST", "/some", body)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Content-Length", fmt.Sprintf("%d", body.Len()))

	return req
}

// from issue https://github.com/corazawaf/coraza/issues/159 @zpeasystart
func TestChainEvaluation(t *testing.T) {
	waf := corazawaf.NewWAF()
	waf.RequestBodyAccess = true
	if err := seclang.NewParser(waf).FromString(`
	SecRule REQUEST_FILENAME "@unconditionalMatch" "id:100, phase:2, t:none, log, setvar:'tx.count=+1',chain"
		SecRule ARGS_POST:username "@unconditionalMatch" "t:none, setvar:'tx.count=+2',chain"
			SecRule ARGS_POST:password "@unconditionalMatch" "t:none, setvar:'tx.count=+3'"
	`); err != nil {
		t.Fatal(err)
	}
	if err := waf.Validate(); err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ForceRequestBodyVariable = true
	// request
	rdata := []string{
		"POST /login HTTP/1.1",
		"Accept: */*",
		"Accept-Encoding: gzip, deflate",
		"Connection: close",
		"Origin: http://test.com",
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
		"Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
		"Referer: http://somehost.com/login.jsp",
		"X-Requested-With: XMLHttpRequest",
		"Content-Length: 59",
		"Accept-Language: zh-CN,zh;q=0.9",
		"",
		"username=root&password=123&rememberMe=on&time=1644979180757",
	}
	data := bytes.NewBuffer([]byte(strings.Join(rdata, "\r\n")))
	req, err := http.ReadRequest(bufio.NewReader(data))
	if err != nil {
		t.Errorf("Description HTTP request parsing failed")
	}

	_, err = processRequest(tx, req)
	if err != nil {
		t.Errorf("Failed to load the HTTP request")
	}

	rulesCounter := 0
	r := waf.Rules.FindByID(100)
	for r != nil {
		rulesCounter++
		r = r.Chain
	}
	if want, have := 3, rulesCounter; want != have {
		t.Errorf("failed to compile multiple chains, want: %d, have: %d", want, have)
	}

	m, err := macro.NewMacro("%{tx.count}")
	if err != nil {
		t.Fatalf("failed to initialize the macro: %v", err)
	}

	txCount, _ := strconv.Atoi(m.Expand(tx))
	if want, have := 6, txCount; want != have {
		t.Errorf("incorrect counter, want %d, have %d", want, have)
	}
}

func errLogger(t *testing.T) func(rule types.MatchedRule) {
	return func(rule types.MatchedRule) {
		t.Log(rule.ErrorLog())
	}
}

type testLogOutput struct {
	t *testing.T
}

func (l testLogOutput) Write(p []byte) (int, error) {
	l.t.Log(string(p))
	return len(p), nil
}

type httpTest struct {
	http2                   bool
	reqURI                  string
	reqBody                 string
	echoReqBody             bool
	reqBodyLimit            int
	shouldRejectOnBodyLimit bool
	respHeaders             map[string]string
	respBody                string
	expectedProto           string
	expectedStatus          int
	expectedRespHeadersKeys []string
	expectedRespBody        string
}

var expectedNoBlockingHeaders = []string{"Content-Type", "Content-Length", "Coraza-Middleware", "Date"}

// When an interruption occour, we are expecting that no response headers are sent back to the client.
var expectedBlockingHeaders = []string{"Content-Length", "Date"}

func TestHttpServer(t *testing.T) {
	tests := map[string]httpTest{
		/*"no blocking": {
			reqURI:                  "/hello",
			expectedProto:           "HTTP/1.1",
			expectedStatus:          201,
			expectedRespHeadersKeys: expectedNoBlockingHeaders,
		},
		"no blocking HTTP/2": {
			http2:                   true,
			reqURI:                  "/hello",
			expectedProto:           "HTTP/2.0",
			expectedStatus:          201,
			expectedRespHeadersKeys: expectedNoBlockingHeaders,
		},
		"args blocking": {
			reqURI:                  "/hello?id=0",
			expectedProto:           "HTTP/1.1",
			expectedStatus:          403,
			expectedRespHeadersKeys: expectedBlockingHeaders,
		},
		"request body blocking": {
			reqURI:                  "/hello",
			reqBody:                 "eval('cat /etc/passwd')",
			expectedProto:           "HTTP/1.1",
			expectedStatus:          403,
			expectedRespHeadersKeys: expectedBlockingHeaders,
		},
		"request body larger than limit (process partial)": {
			reqURI:      "/hello",
			reqBody:     "eval('cat /etc/passwd')",
			echoReqBody: true,
			// Coraza only sees eva, not eval
			reqBodyLimit:            3,
			expectedProto:           "HTTP/1.1",
			expectedStatus:          201,
			expectedRespHeadersKeys: expectedNoBlockingHeaders,
			expectedRespBody:        "eval('cat /etc/passwd')",
		},
		"request body larger than limit (reject)": {
			reqURI:                  "/hello",
			reqBody:                 "something larger than 3",
			echoReqBody:             true,
			reqBodyLimit:            3,
			shouldRejectOnBodyLimit: true,
			expectedProto:           "HTTP/1.1",
			expectedStatus:          413,
			expectedRespHeadersKeys: expectedBlockingHeaders,
			expectedRespBody:        "",
		},
		"response headers blocking": {
			reqURI:                  "/hello",
			respHeaders:             map[string]string{"foo": "bar"},
			expectedProto:           "HTTP/1.1",
			expectedStatus:          401,
			expectedRespHeadersKeys: expectedBlockingHeaders,
		},
		"response body not blocking": {
			reqURI:                  "/hello",
			respBody:                "true negative response body",
			expectedProto:           "HTTP/1.1",
			expectedStatus:          201,
			expectedRespHeadersKeys: expectedNoBlockingHeaders,
			expectedRespBody:        "true negative response body",
		},
		"response body blocking": {
			reqURI:                  "/hello",
			respBody:                "password=xxxx",
			expectedProto:           "HTTP/1.1",
			expectedStatus:          403,
			expectedRespBody:        "", // blocking at response body phase means returning it empty
			expectedRespHeadersKeys: expectedBlockingHeaders,
		},
		"allow": {
			reqURI:                  "/allow_me",
			expectedProto:           "HTTP/1.1",
			expectedStatus:          201,
			expectedRespHeadersKeys: expectedNoBlockingHeaders,
		},
		"deny passes over allow due to ordering": {
			reqURI:                  "/allow_me?id=0",
			expectedProto:           "HTTP/1.1",
			expectedStatus:          403,
			expectedRespHeadersKeys: expectedBlockingHeaders,
		},*/
		"deny based on number of post arguments matching a name": {
			reqURI:                  "/hello?foobar=1&foobar=2",
			expectedProto:           "HTTP/1.1",
			expectedStatus:          403,
			expectedRespHeadersKeys: expectedBlockingHeaders,
		},
	}

	logger := debuglog.Default().
		WithOutput(testLogOutput{t}).
		WithLevel(debuglog.LevelInfo)

	// Perform tests
	for name, tCase := range tests {
		t.Run(name, func(t *testing.T) {
			limitAction := "ProcessPartial"
			if tCase.shouldRejectOnBodyLimit {
				limitAction = "Reject"
			}
			conf := coraza.NewWAFConfig().
				WithDirectives(`
	# This is a comment
	SecDebugLogLevel 9
	SecRequestBodyAccess On
	SecResponseBodyAccess On
	SecResponseBodyMimeType text/plain
	SecRequestBodyLimitAction ` + limitAction + `
	SecRule ARGS:id "@eq 0" "id:10, phase:1,deny, status:403,msg:'Invalid id',log,auditlog"
	SecRule REQUEST_BODY "@contains eval" "id:100, phase:2,deny, status:403,msg:'Invalid request body',log,auditlog"
	SecRule RESPONSE_HEADERS:Foo "@pm bar" "id:199,phase:3,deny,t:lowercase,deny, status:401,msg:'Invalid response header',log,auditlog"
	SecRule RESPONSE_BODY "@contains password" "id:200, phase:4,deny, status:403,msg:'Invalid response body',log,auditlog"
	SecRule REQUEST_URI "/allow_me" "id:9,phase:1,allow,msg:'ALLOWED'"
	SecRule &ARGS_GET_NAMES:foobar "@eq 2" "id:11,phase:1,deny, status:403,msg:'Invalid foobar',log,auditlog"
`).WithErrorCallback(errLogger(t)).WithDebugLogger(logger)
			if l := tCase.reqBodyLimit; l > 0 {
				conf = conf.WithRequestBodyAccess().WithRequestBodyLimit(l).WithRequestBodyInMemoryLimit(l)
			}
			waf, err := coraza.NewWAF(conf)
			if err != nil {
				t.Fatal(err)
			}
			runAgainstWAF(t, tCase, waf)
		})
	}
}

func TestHttpServerWithRuleEngineOff(t *testing.T) {
	tests := map[string]httpTest{
		"no blocking true negative": {
			reqURI:                  "/hello",
			expectedProto:           "HTTP/1.1",
			expectedStatus:          201,
			respBody:                "Hello!",
			expectedRespHeadersKeys: expectedNoBlockingHeaders,
			expectedRespBody:        "Hello!",
		},
		"no blocking true positive header phase": {
			reqURI:                  "/hello?id=0",
			expectedProto:           "HTTP/1.1",
			expectedStatus:          201,
			respBody:                "Downstream works!",
			expectedRespHeadersKeys: expectedNoBlockingHeaders,
			expectedRespBody:        "Downstream works!",
		},
		"no blocking true positive body phase": {
			reqURI:                  "/hello",
			reqBody:                 "eval('cat /etc/passwd')",
			expectedProto:           "HTTP/1.1",
			expectedStatus:          201,
			respBody:                "Waf is Off!",
			expectedRespHeadersKeys: expectedNoBlockingHeaders,
			expectedRespBody:        "Waf is Off!",
		},
	}
	logger := debuglog.Default().
		WithOutput(testLogOutput{t}).
		WithLevel(debuglog.LevelInfo)

	// Perform tests
	for name, tCase := range tests {
		t.Run(name, func(t *testing.T) {
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().
				WithDirectives(`
			SecRuleEngine Off
			SecRequestBodyAccess On
			SecRule ARGS:id "@eq 0" "id:1, phase:1,deny, status:403,msg:'Invalid id',log,auditlog"
			SecRule REQUEST_BODY "@contains eval" "id:100, phase:2,deny, status:403,msg:'Invalid request body',log,auditlog"
			`).WithErrorCallback(errLogger(t)).WithDebugLogger(logger))
			if err != nil {
				t.Fatal(err)
			}
			runAgainstWAF(t, tCase, waf)
		})
	}
}

func runAgainstWAF(t *testing.T, tCase httpTest, waf coraza.WAF) {
	t.Helper()
	serverErrC := make(chan error, 1)
	defer close(serverErrC)

	// Spin up the test server
	ts := httptest.NewUnstartedServer(WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if want, have := tCase.expectedProto, req.Proto; want != have {
			t.Errorf("unexpected proto, want: %s, have: %s", want, have)
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Add("coraza-middleware", "true")
		for k, v := range tCase.respHeaders {
			w.Header().Set(k, v)
		}
		w.WriteHeader(201)
		if tCase.echoReqBody {
			buf, err := io.ReadAll(req.Body)
			if err != nil {
				serverErrC <- err
			}
			if _, err := w.Write(buf); err != nil {
				serverErrC <- err
			}
		} else {
			if _, err := w.Write([]byte(tCase.respBody)); err != nil {
				serverErrC <- err
			}
		}
	})))
	if tCase.http2 {
		ts.EnableHTTP2 = true
		ts.StartTLS()
	} else {
		ts.Start()
	}
	defer ts.Close()

	var reqBody io.Reader
	if tCase.reqBody != "" {
		reqBody = strings.NewReader(tCase.reqBody)
	}
	req, _ := http.NewRequest("POST", ts.URL+tCase.reqURI, reqBody)
	// When sending a POST request, the "application/x-www-form-urlencoded" content-type header is needed
	// being the only content-type for which by default Coraza enforces the request body processing.
	// See https://github.com/corazawaf/coraza/issues/438
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("unexpected error when performing the request: %v", err)
	}

	if want, have := tCase.expectedStatus, res.StatusCode; want != have {
		t.Errorf("unexpected status code, want: %d, have: %d", want, have)
	}

	if !keysExistInMap(t, tCase.expectedRespHeadersKeys, res.Header) {
		t.Errorf("unexpected response headers, expected keys: %v, headers: %v", tCase.expectedRespHeadersKeys, res.Header)
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("unexpected error when reading the response body: %v", err)
	}

	if want, have := tCase.expectedRespBody, string(resBody); want != have {
		t.Errorf("unexpected response body, want: %q, have %q", want, have)
	}

	err = res.Body.Close()
	if err != nil {
		t.Errorf("failed to close the body: %v", err)
	}

	select {
	case err = <-serverErrC:
		t.Errorf("unexpected error from server when writing response body: %v", err)
	default:
		return
	}
}

func keysExistInMap(t *testing.T, keys []string, m map[string][]string) bool {
	t.Helper()
	if len(keys) != len(m) {
		return false
	}
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			return false
		}
	}
	return true
}

func TestObtainStatusCodeFromInterruptionOrDefault(t *testing.T) {
	tCases := map[string]struct {
		interruptionCode   int
		interruptionAction string
		defaultCode        int
		expectedCode       int
	}{
		"action deny with no code": {
			interruptionAction: "deny",
			expectedCode:       403,
		},
		"action deny with code": {
			interruptionAction: "deny",
			interruptionCode:   202,
			expectedCode:       202,
		},
		"default code": {
			defaultCode:  204,
			expectedCode: 204,
		},
	}

	for name, tCase := range tCases {
		t.Run(name, func(t *testing.T) {
			want := tCase.expectedCode
			have := obtainStatusCodeFromInterruptionOrDefault(&types.Interruption{
				Status: tCase.interruptionCode,
				Action: tCase.interruptionAction,
			}, tCase.defaultCode)
			if want != have {
				t.Errorf("unexpected status code, want %d, have %d", want, have)
			}
		})
	}
}

func TestHandlerWithNilWAF(t *testing.T) {
	delegateHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	wrappedHandler := WrapHandler(nil, delegateHandler).(http.HandlerFunc)
	if want, have := fmt.Sprintf("%v", delegateHandler), fmt.Sprintf("%v", wrappedHandler); want != have {
		t.Errorf("unexpected wrapped handler")
	}
}

func TestHandlerAPI(t *testing.T) {
	testCases := map[string]struct {
		handler            http.HandlerFunc
		expectedStatusCode int
	}{
		"empty handler": {
			handler:            func(w http.ResponseWriter, r *http.Request) {},
			expectedStatusCode: 200,
		},
		"read the request body": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				b, err := io.ReadAll(r.Body)
				if err != nil {
					panic(err)
				}
				if string(b) != "the payload" {
					panic("unexpected payload")
				}
			},
			expectedStatusCode: 200,
		},
		"status code but no body": {
			handler:            func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) },
			expectedStatusCode: 201,
		},
		"double status code but no body": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(201)
				w.WriteHeader(202)
			},
			expectedStatusCode: 201,
		},
		"no status code and body": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte{1, 2, 3})
			},
			expectedStatusCode: 200,
		},
		"status code and body": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(201)
				_, _ = w.Write([]byte{1, 2, 3})
			},
			expectedStatusCode: 201,
		},
		"status code and multiwrite body": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(201)
				_, _ = w.Write([]byte{1, 2, 3})
				_, _ = w.Write([]byte{4, 5, 6})
			},
			expectedStatusCode: 201,
		},
	}

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRequestBodyLimit(3))
	if err != nil {
		t.Fatalf("unexpected error while creating the WAF: %s", err.Error())
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(WrapHandler(waf, tCase.handler))
			defer srv.Close()

			res, err := http.Post(srv.URL, "application/json", bytes.NewBufferString("the payload"))
			if err != nil {
				t.Fatalf("unexpected error while performing the request: %s", err.Error())
			}
			defer res.Body.Close()

			if want, have := tCase.expectedStatusCode, res.StatusCode; want != have {
				t.Fatalf("unexpected status code, want: %d, have: %d", want, have)
			}

			_, err = io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("unexpected error while reading the body: %s", err.Error())
			}
		})
	}
}
