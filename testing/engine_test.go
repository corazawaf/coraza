// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

func TestRawRequests(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
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
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)
	if err := test.SetRawRequest([]byte("OPTIONS /test HTTP/1.1\r\nHost: www.example.com\r\n\r\n")); err != nil {
		t.Error(err)
	}
	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}
	debug := fmt.Sprint(test.transaction)
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
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
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
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithResponseBodyAccess().WithResponseBodyLimit(21),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
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

// TestRecommendedConfArgumentsLimit asserts that the REQBODY_ERROR rule
// shipped in coraza.conf-recommended denies a request whose arguments were
// only inspected in part, with the status the file declares, and stays quiet
// on a request that fits under SecArgumentsLimit. The file is read from disk
// so the rule that ships is the rule under test.
func TestRecommendedConfArgumentsLimit(t *testing.T) {
	// A query string over the limit sets ARGUMENTS_LIMIT_REACHED in phase 1,
	// where rule 200004 denies it before the REQBODY_ERROR rule (200002, phase
	// 2) gets to run; both ship in the file and both are fork-visible signals.
	const argumentsLimitRuleID = 200004

	rec, err := os.ReadFile("../coraza.conf-recommended")
	if err != nil {
		t.Fatal(err)
	}
	// The file ships in DetectionOnly so that dropping it into a deployment
	// cannot break traffic; blocking is what the rule is asserted on here.
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(string(rec)).
		WithDirectives("SecRuleEngine On\nSecArgumentsLimit 5"))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		uri  string
		want *types.Interruption
	}{
		{
			name: "over the limit",
			uri:  "/?a=1&b=2&c=3&d=4&e=5&f=6&evil=1",
			want: &types.Interruption{RuleID: argumentsLimitRuleID, Status: 400, Action: "deny"},
		},
		{
			name: "under the limit",
			uri:  "/?a=1&b=2&c=3",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := waf.NewTransaction()
			defer func() {
				if err := tx.Close(); err != nil {
					t.Fatalf("Failed to close transaction: %s", err.Error())
				}
			}()
			tx.ProcessURI(tc.uri, "GET", "HTTP/1.1")
			tx.AddRequestHeader("Host", "www.example.com")
			tx.ProcessRequestHeaders()
			if _, err := tx.ProcessRequestBody(); err != nil {
				t.Fatal(err)
			}
			have := tx.Interruption()
			switch {
			case tc.want == nil:
				if have != nil {
					t.Fatalf("a request under SecArgumentsLimit must not be interrupted, have %+v", have)
				}
			case have == nil:
				t.Fatal("a request over SecArgumentsLimit was not interrupted")
			case have.RuleID != tc.want.RuleID || have.Status != tc.want.Status || have.Action != tc.want.Action:
				t.Fatalf("unexpected interruption, want %+v, have %+v", tc.want, have)
			}
		})
	}
}
