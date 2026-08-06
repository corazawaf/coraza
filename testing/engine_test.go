// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/corazawaf/coraza/v3"
)

func TestRawRequests(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)
	err := test.SetRawRequest([]byte("OPTIONS /test HTTP/1.1\r\nHost: www.example.com\r\n\r\n"))
	require.NoError(t, err)
	require.Equal(t, "OPTIONS", test.RequestMethod)
	require.Equal(t, "/test", test.RequestURI)
}

func TestDebug(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)
	err := test.SetRawRequest([]byte("OPTIONS /test HTTP/1.1\r\nHost: www.example.com\r\n\r\n"))
	require.NoError(t, err)
	err = test.RunPhases()
	require.NoError(t, err)
	debug := fmt.Sprint(test.transaction)
	expected := []string{
		"REQUEST_URI: /test",
		"REQUEST_METHOD: OPTIONS",
	}
	for _, e := range expected {
		require.Contains(t, debug, e)
	}
}

func TestRequest(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)
	req := buildRequest("GET", "/test")
	err := test.SetRawRequest([]byte(req))
	require.NoError(t, err)
	err = test.RunPhases()
	require.NoError(t, err)
	req = test.Request()
	expected := []string{
		"GET /test HTTP/1.1",
		"Host: www.example.com",
	}
	for _, e := range expected {
		require.Contains(t, req, e)
	}
}

func TestResponse(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithResponseBodyAccess().WithResponseBodyLimit(21),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	req := buildRequest("POST", "/test")
	err = test.SetRawRequest([]byte(req))
	require.NoError(t, err)
	test.ResponseHeaders["content-type"] = "application/x-www-form-urlencoded"
	err = test.SetResponseBody("someoutput=withvalue")
	require.NoError(t, err)
	err = test.RunPhases()
	require.NoError(t, err)
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
