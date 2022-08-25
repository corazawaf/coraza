// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
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
	debug := test.transaction.Debug()
	expected := []string{
		"REQUEST_URI: /test",
		"REQUEST_METHOD: OPTIONS",
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
