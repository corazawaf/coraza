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

package testing

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v2"
)

func TestRawRequests(t *testing.T) {
	waf := coraza.NewWaf()
	test := NewTest("test", waf)
	if err := test.SetRawRequest([]byte("OPTIONS /test HTTP/1.1\r\nHost: www.example.com\r\n\r\n")); err != nil {
		t.Error(err)
	}
	if test.RequestMethod != "OPTIONS" {
		t.Errorf("Expected OPTIONS, got %s", test.RequestMethod)
	}
	if test.RequestURI != "/test" {
		t.Errorf("Expected /test, got %s", test.RequestURI)
	}
}

func TestDebug(t *testing.T) {
	waf := coraza.NewWaf()
	test := NewTest("test", waf)
	if err := test.SetRawRequest([]byte("OPTIONS /test HTTP/1.1\r\nHost: www.example.com\r\n\r\n")); err != nil {
		t.Error(err)
	}
	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}
	debug := test.String()
	expected := []string{
		"REQUEST_URI:\n-->/test",
		"REQUEST_METHOD:\n-->OPTIONS",
	}
	for _, e := range expected {
		if !strings.Contains(debug, e) {
			t.Errorf("Expected %s, got %s", e, debug)
		}
	}
}

func TestRequest(t *testing.T) {
	waf := coraza.NewWaf()
	test := NewTest("test", waf)
	req := buildRequest("GET", "/test")
	if err := test.SetRawRequest([]byte(req)); err != nil {
		t.Error(err)
	}
	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}
	req = test.Request()
	expected := []string{
		"GET /test HTTP/1.1",
		"Host: www.example.com",
	}
	for _, e := range expected {
		if !strings.Contains(req, e) {
			t.Errorf("Expected %s, got %s", e, req)
		}
	}
}

func TestResponse(t *testing.T) {
	waf := coraza.NewWaf()
	waf.ResponseBodyAccess = true
	test := NewTest("test", waf)
	req := buildRequest("POST", "/test")
	if err := test.SetRawRequest([]byte(req)); err != nil {
		t.Error(err)
	}
	test.ResponseHeaders["content-type"] = "application/x-www-form-urlencoded"
	if err := test.SetResponseBody("someoutput=withvalue"); err != nil {
		t.Error(err)
	}
	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}
	/*
		if s := test.Transaction().GetCollection(variables.ArgsPost).GetFirstString("someoutput"); s != "withvalue" {
			t.Errorf("Expected someoutput=withvalue, got %s", s)
		}
	*/
}

func buildRequest(method, uri string) string {
	return strings.Join([]string{
		method + " " + uri + " HTTP/1.1",
		"Host: www.example.com",
	}, "\r\n")
}
