// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/testing/profile"
)

func TestOutputInterruptionErrors_NoInterruptionExpectedButGot(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /block" "id:1,phase:1,deny,status:403"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/block"
	test.ExpectedOutput.Interruption = nil // No interruption expected

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputInterruptionErrors()
	if len(errors) == 0 {
		t.Error("Expected errors when interruption happened but wasn't expected")
	}
	expectedMsg := "Expected no interruption, but transaction was interrupted"
	if !strings.Contains(errors[0], expectedMsg) {
		t.Errorf("Expected error message to contain '%s', got: %s", expectedMsg, errors[0])
	}
	if !strings.Contains(errors[0], "rule 1") {
		t.Errorf("Expected error message to contain rule ID, got: %s", errors[0])
	}
}

func TestOutputInterruptionErrors_InterruptionExpectedButDidntHappen(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/allow"
	test.ExpectedOutput.Interruption = &profile.ExpectedInterruption{
		Action: "deny",
		Status: 403,
		RuleID: 1,
	}

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputInterruptionErrors()
	if len(errors) == 0 {
		t.Error("Expected errors when interruption was expected but didn't happen")
	}
	expectedMsg := "Expected interruption, but transaction was not interrupted"
	if errors[0] != expectedMsg {
		t.Errorf("Expected error message '%s', got: %s", expectedMsg, errors[0])
	}
}

func TestOutputInterruptionErrors_InterruptionDetailsMatch(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /block" "id:123,phase:1,deny,status:403"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/block"
	test.ExpectedOutput.Interruption = &profile.ExpectedInterruption{
		Action: "deny",
		Status: 403,
		Data:   "",
		RuleID: 123,
	}

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputInterruptionErrors()
	if len(errors) != 0 {
		t.Errorf("Expected no errors when interruption details match, got: %v", errors)
	}
}

func TestOutputInterruptionErrors_ActionMismatch(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /block" "id:1,phase:1,deny,status:403"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/block"
	test.ExpectedOutput.Interruption = &profile.ExpectedInterruption{
		Action: "drop",
		Status: 403,
		RuleID: 1,
	}

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputInterruptionErrors()
	if len(errors) == 0 {
		t.Error("Expected errors when interruption action doesn't match")
	}
	expectedMsg := "Interruption.Action: expected: 'drop', got: 'deny'"
	if errors[0] != expectedMsg {
		t.Errorf("Expected error message '%s', got: %s", expectedMsg, errors[0])
	}
}

func TestOutputInterruptionErrors_StatusMismatch(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /block" "id:1,phase:1,deny,status:403"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/block"
	test.ExpectedOutput.Interruption = &profile.ExpectedInterruption{
		Action: "deny",
		Status: 404,
		RuleID: 1,
	}

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputInterruptionErrors()
	if len(errors) == 0 {
		t.Error("Expected errors when interruption status doesn't match")
	}
	expectedMsg := "Interruption.Status: expected: '404', got: '403'"
	if errors[0] != expectedMsg {
		t.Errorf("Expected error message '%s', got: %s", expectedMsg, errors[0])
	}
}

func TestOutputInterruptionErrors_RuleIDMismatch(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /block" "id:123,phase:1,deny,status:403"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/block"
	test.ExpectedOutput.Interruption = &profile.ExpectedInterruption{
		Action: "deny",
		Status: 403,
		RuleID: 456,
	}

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputInterruptionErrors()
	if len(errors) == 0 {
		t.Error("Expected errors when interruption RuleID doesn't match")
	}
	expectedMsg := "Interruption.RuleID: expected: '456', got: '123'"
	if errors[0] != expectedMsg {
		t.Errorf("Expected error message '%s', got: %s", expectedMsg, errors[0])
	}
}

func TestOutputErrors_LogContains(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:100,phase:1,log,msg:'Test message'"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/test"
	test.ExpectedOutput.LogContains = "Test message"

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputErrors()
	if len(errors) != 0 {
		t.Errorf("Expected no errors when log contains expected message, got: %v", errors)
	}
}

func TestOutputErrors_LogContainsMissing(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:100,phase:1,log,msg:'Different message'"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/test"
	test.ExpectedOutput.LogContains = "Missing message"

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputErrors()
	if len(errors) == 0 {
		t.Error("Expected errors when log doesn't contain expected message")
	}
	expectedMsg := "Expected log to contain 'Missing message'"
	if errors[0] != expectedMsg {
		t.Errorf("Expected error message '%s', got: %s", expectedMsg, errors[0])
	}
}

func TestOutputErrors_NoLogContains(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:100,phase:1,log,msg:'Test message'"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/test"
	test.ExpectedOutput.NoLogContains = "Should not be here"

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputErrors()
	if len(errors) != 0 {
		t.Errorf("Expected no errors when log doesn't contain unwanted message, got: %v", errors)
	}
}

func TestOutputErrors_NoLogContainsFails(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:100,phase:1,log,msg:'Forbidden message'"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/test"
	test.ExpectedOutput.NoLogContains = "Forbidden message"

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputErrors()
	if len(errors) == 0 {
		t.Error("Expected errors when log contains unwanted message")
	}
	expectedMsg := "Expected log to not contain 'Forbidden message'"
	if errors[0] != expectedMsg {
		t.Errorf("Expected error message '%s', got: %s", expectedMsg, errors[0])
	}
}

func TestOutputErrors_TriggeredRules(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test1" "id:101,phase:1,log"
				SecRule REQUEST_URI "@streq /test2" "id:102,phase:1,log"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/test1"
	test.ExpectedOutput.TriggeredRules = []int{101}

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputErrors()
	if len(errors) != 0 {
		t.Errorf("Expected no errors when expected rules are triggered, got: %v", errors)
	}
}

func TestOutputErrors_TriggeredRulesNotTriggered(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:101,phase:1,log"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/other"
	test.ExpectedOutput.TriggeredRules = []int{101, 102}

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputErrors()
	if len(errors) != 2 {
		t.Errorf("Expected 2 errors for 2 missing rules, got: %v", errors)
	}
	if !strings.Contains(errors[0], "Expected rule '101' to be triggered") {
		t.Errorf("Expected error about rule 101, got: %s", errors[0])
	}
	if !strings.Contains(errors[1], "Expected rule '102' to be triggered") {
		t.Errorf("Expected error about rule 102, got: %s", errors[1])
	}
}

func TestOutputErrors_NonTriggeredRules(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:101,phase:1,log"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/other"
	test.ExpectedOutput.NonTriggeredRules = []int{101}

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputErrors()
	if len(errors) != 0 {
		t.Errorf("Expected no errors when rules are not triggered as expected, got: %v", errors)
	}
}

func TestOutputErrors_NonTriggeredRulesActuallyTriggered(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:101,phase:1,log"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/test"
	test.ExpectedOutput.NonTriggeredRules = []int{101}

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	errors := test.OutputErrors()
	if len(errors) == 0 {
		t.Error("Expected errors when non-triggered rules are actually triggered")
	}
	expectedMsg := "Expected rule '101' to not be triggered"
	if errors[0] != expectedMsg {
		t.Errorf("Expected error message '%s', got: %s", expectedMsg, errors[0])
	}
}

func TestSetEncodedRequest(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	// Base64 encoded: "GET /encoded HTTP/1.1\r\nHost: example.com\r\n\r\n"
	encodedReq := "R0VUIC9lbmNvZGVkIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KDQo="

	if err := test.SetEncodedRequest(encodedReq); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if test.RequestMethod != "GET" {
		t.Errorf("Expected method GET, got %s", test.RequestMethod)
	}
	if test.RequestURI != "/encoded" {
		t.Errorf("Expected URI /encoded, got %s", test.RequestURI)
	}
	if test.RequestProtocol != "HTTP/1.1" {
		t.Errorf("Expected protocol HTTP/1.1, got %s", test.RequestProtocol)
	}
	if test.RequestHeaders["Host"] != "example.com" {
		t.Errorf("Expected Host header example.com, got %s", test.RequestHeaders["Host"])
	}
}

func TestSetEncodedRequest_Empty(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	if err := test.SetEncodedRequest(""); err != nil {
		t.Errorf("Empty encoded request should not error, got: %v", err)
	}
}

func TestSetEncodedRequest_Invalid(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	if err := test.SetEncodedRequest("invalid-base64!!!"); err == nil {
		t.Error("Expected error for invalid base64, got nil")
	}
}

func TestSetRawRequest_WithNewlineOnly(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	req := "POST /path HTTP/1.1\nHost: www.example.com\nContent-Type: application/json\n\n{\"key\":\"value\"}"
	if err := test.SetRawRequest([]byte(req)); err != nil {
		t.Errorf("Unexpected error with \\n line endings: %v", err)
	}

	if test.RequestMethod != "POST" {
		t.Errorf("Expected POST, got %s", test.RequestMethod)
	}
	if test.RequestHeaders["Content-Type"] != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", test.RequestHeaders["Content-Type"])
	}
}

func TestSetRawRequest_Empty(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	if err := test.SetRawRequest([]byte{}); err != nil {
		t.Errorf("Empty request should not error, got: %v", err)
	}
}

func TestSetRawRequest_InvalidRequestLine(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	// Request line with only 2 parts instead of 3
	req := "GET /path\r\nHost: www.example.com\r\n\r\n"
	if err := test.SetRawRequest([]byte(req)); err == nil {
		t.Error("Expected error for invalid request line, got nil")
	}
}

func TestSetRawRequest_InvalidHeader(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	// Header without colon
	req := "GET /path HTTP/1.1\r\nInvalidHeader\r\n\r\n"
	if err := test.SetRawRequest([]byte(req)); err == nil {
		t.Error("Expected error for invalid header, got nil")
	}
}

func TestSetRawRequest_SingleLine(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	// Single line request (invalid)
	req := "GET /path HTTP/1.1"
	if err := test.SetRawRequest([]byte(req)); err == nil {
		t.Error("Expected error for single line request, got nil")
	}
}

func TestSetRawRequest_WithBody(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	req := "POST /path HTTP/1.1\r\nHost: www.example.com\r\n\r\ntest=body&data=value"
	if err := test.SetRawRequest([]byte(req)); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// The body should start after the empty line separator when parsed from raw request
	expectedBody := "test=body&data=value"
	if test.body != expectedBody {
		t.Errorf("Expected body '%s', got '%s'", expectedBody, test.body)
	}
}

func TestDisableMagic(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)
	test.DisableMagic()

	bodyContent := "test body content"
	if err := test.SetRequestBody(bodyContent); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// With magic disabled, content-length should not be set automatically
	if _, ok := test.RequestHeaders["content-length"]; ok {
		t.Error("Expected content-length to not be set when magic is disabled")
	}
}

func TestMagicEnabled(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)
	// Magic is enabled by default

	bodyContent := "test body content"
	if err := test.SetRequestBody(bodyContent); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// With magic enabled, content-length should be set automatically
	if test.RequestHeaders["content-length"] != "17" {
		t.Errorf("Expected content-length to be '17', got '%s'", test.RequestHeaders["content-length"])
	}
}

func TestSetRequestBody_Nil(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	if err := test.SetRequestBody(nil); err != nil {
		t.Errorf("Nil body should not error, got: %v", err)
	}
}

func TestSetRequestBody_EmptyString(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	if err := test.SetRequestBody(""); err != nil {
		t.Errorf("Empty body should not error, got: %v", err)
	}
}

func TestSetResponseBody_Nil(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithResponseBodyAccess(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)

	if err := test.SetResponseBody(nil); err != nil {
		t.Errorf("Nil response body should not error, got: %v", err)
	}
}

func TestSetResponseBody_EmptyString(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithResponseBodyAccess(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)

	if err := test.SetResponseBody(""); err != nil {
		t.Errorf("Empty response body should not error, got: %v", err)
	}
}

func TestBodyToString_StringArray(t *testing.T) {
	result := bodyToString([]string{"line1", "line2", "line3"})
	expected := "line1\r\nline2\r\nline3\r\n\r\n"
	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}
}

func TestBodyToString_String(t *testing.T) {
	input := "simple string body"
	result := bodyToString(input)
	if result != input {
		t.Errorf("Expected '%s', got '%s'", input, result)
	}
}

func TestBodyToString_InvalidType(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for invalid type, but didn't panic")
		}
	}()
	bodyToString(123) // Should panic
}

func TestLogContains(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:200,phase:1,log,msg:'Unique test message'"
			`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	test := NewTest("test", waf)
	test.RequestURI = "/test"

	if err := test.RunPhases(); err != nil {
		t.Error(err)
	}

	if !test.LogContains("Unique test message") {
		t.Error("Expected LogContains to return true for message in log")
	}

	if test.LogContains("Message not in log") {
		t.Error("Expected LogContains to return false for message not in log")
	}
}

func TestTransaction(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	tx := test.Transaction()
	if tx == nil {
		t.Error("Expected non-nil transaction")
	}
}
