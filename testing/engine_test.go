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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRawRequests(t *testing.T) {
	waf := coraza.NewWaf()
	test := NewTest("test", waf)
	err := test.SetRawRequest([]byte("OPTIONS /test HTTP/1.1\r\nHost: www.example.com\r\n\r\n"))
	require.NoError(t, err)
	require.Equal(t, "OPTIONS", test.RequestMethod)
	require.Equal(t, "/test", test.RequestURI)
}

func TestDebug(t *testing.T) {
	waf := coraza.NewWaf()
	test := NewTest("test", waf)

	err := test.SetRawRequest([]byte("OPTIONS /test HTTP/1.1\r\nHost: www.example.com\r\n\r\n"))
	require.NoError(t, err)

	err = test.RunPhases()
	require.NoError(t, err)

	debug := test.String()
	expected := []string{
		"REQUEST_URI:\n-->/test",
		"REQUEST_METHOD:\n-->OPTIONS",
	}
	for _, e := range expected {
		assert.Contains(t, debug, e)
	}
}

func TestRequest(t *testing.T) {
	waf := coraza.NewWaf()
	test := NewTest("test", waf)
	req := buildRequest(t, "GET", "/test")
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
		assert.Contains(t, req, e)
	}
}

func TestResponse(t *testing.T) {
	waf := coraza.NewWaf()
	waf.ResponseBodyAccess = true
	test := NewTest("test", waf)
	req := buildRequest(t, "POST", "/test")

	err := test.SetRawRequest([]byte(req))
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

func buildRequest(t *testing.T, method, uri string) string {
	t.Helper()
	return strings.Join([]string{
		method + " " + uri + " HTTP/1.1",
		"Host: www.example.com",
	}, "\r\n")
}
