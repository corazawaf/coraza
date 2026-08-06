// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	"testing"

	"github.com/stretchr/testify/require"

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
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/block"
	test.ExpectedOutput.Interruption = nil // No interruption expected

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputInterruptionErrors()
	require.NotEmpty(t, errors, "Expected errors when interruption happened but wasn't expected")
	expectedMsg := "Expected no interruption, but transaction was interrupted"
	require.Contains(t, errors[0], expectedMsg)
	require.Contains(t, errors[0], "rule 1")
}

func TestOutputInterruptionErrors_InterruptionExpectedButDidntHappen(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/allow"
	test.ExpectedOutput.Interruption = &profile.ExpectedInterruption{
		Action: "deny",
		Status: 403,
		RuleID: 1,
	}

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputInterruptionErrors()
	require.NotEmpty(t, errors, "Expected errors when interruption was expected but didn't happen")
	expectedMsg := "Expected interruption, but transaction was not interrupted"
	require.Equal(t, expectedMsg, errors[0])
}

func TestOutputInterruptionErrors_InterruptionDetailsMatch(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /block" "id:123,phase:1,deny,status:403"
			`),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/block"
	test.ExpectedOutput.Interruption = &profile.ExpectedInterruption{
		Action: "deny",
		Status: 403,
		Data:   "",
		RuleID: 123,
	}

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputInterruptionErrors()
	require.Empty(t, errors)
}

func TestOutputInterruptionErrors_ActionMismatch(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /block" "id:1,phase:1,deny,status:403"
			`),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/block"
	test.ExpectedOutput.Interruption = &profile.ExpectedInterruption{
		Action: "drop",
		Status: 403,
		RuleID: 1,
	}

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputInterruptionErrors()
	require.NotEmpty(t, errors, "Expected errors when interruption action doesn't match")
	expectedMsg := "Interruption.Action: expected: 'drop', got: 'deny'"
	require.Equal(t, expectedMsg, errors[0])
}

func TestOutputInterruptionErrors_StatusMismatch(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /block" "id:1,phase:1,deny,status:403"
			`),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/block"
	test.ExpectedOutput.Interruption = &profile.ExpectedInterruption{
		Action: "deny",
		Status: 404,
		RuleID: 1,
	}

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputInterruptionErrors()
	require.NotEmpty(t, errors, "Expected errors when interruption status doesn't match")
	expectedMsg := "Interruption.Status: expected: '404', got: '403'"
	require.Equal(t, expectedMsg, errors[0])
}

func TestOutputInterruptionErrors_RuleIDMismatch(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /block" "id:123,phase:1,deny,status:403"
			`),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/block"
	test.ExpectedOutput.Interruption = &profile.ExpectedInterruption{
		Action: "deny",
		Status: 403,
		RuleID: 456,
	}

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputInterruptionErrors()
	require.NotEmpty(t, errors, "Expected errors when interruption RuleID doesn't match")
	expectedMsg := "Interruption.RuleID: expected: '456', got: '123'"
	require.Equal(t, expectedMsg, errors[0])
}

func TestOutputErrors_LogContains(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:100,phase:1,log,msg:'Test message'"
			`),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/test"
	test.ExpectedOutput.LogContains = "Test message"

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputErrors()
	require.Empty(t, errors)
}

func TestOutputErrors_LogContainsMissing(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:100,phase:1,log,msg:'Different message'"
			`),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/test"
	test.ExpectedOutput.LogContains = "Missing message"

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputErrors()
	require.NotEmpty(t, errors, "Expected errors when log doesn't contain expected message")
	expectedMsg := "Expected log to contain 'Missing message'"
	require.Equal(t, expectedMsg, errors[0])
}

func TestOutputErrors_NoLogContains(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:100,phase:1,log,msg:'Test message'"
			`),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/test"
	test.ExpectedOutput.NoLogContains = "Should not be here"

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputErrors()
	require.Empty(t, errors)
}

func TestOutputErrors_NoLogContainsFails(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:100,phase:1,log,msg:'Forbidden message'"
			`),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/test"
	test.ExpectedOutput.NoLogContains = "Forbidden message"

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputErrors()
	require.NotEmpty(t, errors, "Expected errors when log contains unwanted message")
	expectedMsg := "Expected log to not contain 'Forbidden message'"
	require.Equal(t, expectedMsg, errors[0])
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
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/test1"
	test.ExpectedOutput.TriggeredRules = []int{101}

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputErrors()
	require.Empty(t, errors)
}

func TestOutputErrors_TriggeredRulesNotTriggered(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:101,phase:1,log"
			`),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/other"
	test.ExpectedOutput.TriggeredRules = []int{101, 102}

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputErrors()
	require.Len(t, errors, 2)
	require.Contains(t, errors[0], "Expected rule '101' to be triggered")
	require.Contains(t, errors[1], "Expected rule '102' to be triggered")
}

func TestOutputErrors_NonTriggeredRules(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:101,phase:1,log"
			`),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/other"
	test.ExpectedOutput.NonTriggeredRules = []int{101}

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputErrors()
	require.Empty(t, errors)
}

func TestOutputErrors_NonTriggeredRulesActuallyTriggered(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@streq /test" "id:101,phase:1,log"
			`),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/test"
	test.ExpectedOutput.NonTriggeredRules = []int{101}

	err = test.RunPhases()
	require.NoError(t, err)

	errors := test.OutputErrors()
	require.NotEmpty(t, errors, "Expected errors when non-triggered rules are actually triggered")
	expectedMsg := "Expected rule '101' to not be triggered"
	require.Equal(t, expectedMsg, errors[0])
}

func TestSetEncodedRequest(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	// Base64 encoded: "GET /encoded HTTP/1.1\r\nHost: example.com\r\n\r\n"
	encodedReq := "R0VUIC9lbmNvZGVkIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KDQo="

	err := test.SetEncodedRequest(encodedReq)
	require.NoError(t, err)

	require.Equal(t, "GET", test.RequestMethod)
	require.Equal(t, "/encoded", test.RequestURI)
	require.Equal(t, "HTTP/1.1", test.RequestProtocol)
	require.Equal(t, "example.com", test.RequestHeaders["Host"])
}

func TestSetEncodedRequest_Empty(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	err := test.SetEncodedRequest("")
	require.NoError(t, err)
}

func TestSetEncodedRequest_Invalid(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	err := test.SetEncodedRequest("invalid-base64!!!")
	require.Error(t, err)
}

func TestSetRawRequest_WithNewlineOnly(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	req := "POST /path HTTP/1.1\nHost: www.example.com\nContent-Type: application/json\n\n{\"key\":\"value\"}"
	err := test.SetRawRequest([]byte(req))
	require.NoError(t, err)

	require.Equal(t, "POST", test.RequestMethod)
	require.Equal(t, "application/json", test.RequestHeaders["Content-Type"])
}

func TestSetRawRequest_Empty(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	err := test.SetRawRequest([]byte{})
	require.NoError(t, err)
}

func TestSetRawRequest_InvalidRequestLine(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	// Request line with only 2 parts instead of 3
	req := "GET /path\r\nHost: www.example.com\r\n\r\n"
	err := test.SetRawRequest([]byte(req))
	require.Error(t, err)
}

func TestSetRawRequest_InvalidHeader(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	// Header without colon
	req := "GET /path HTTP/1.1\r\nInvalidHeader\r\n\r\n"
	err := test.SetRawRequest([]byte(req))
	require.Error(t, err)
}

func TestSetRawRequest_SingleLine(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	// Single line request (invalid)
	req := "GET /path HTTP/1.1"
	err := test.SetRawRequest([]byte(req))
	require.Error(t, err)
}

func TestSetRawRequest_WithBody(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	req := "POST /path HTTP/1.1\r\nHost: www.example.com\r\n\r\ntest=body&data=value"
	err := test.SetRawRequest([]byte(req))
	require.NoError(t, err)

	// The body should start after the empty line separator when parsed from raw request
	expectedBody := "test=body&data=value"
	require.Equal(t, expectedBody, test.body)
}

func TestDisableMagic(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)
	test.DisableMagic()

	bodyContent := "test body content"
	err := test.SetRequestBody(bodyContent)
	require.NoError(t, err)

	// With magic disabled, content-length should not be set automatically
	_, ok := test.RequestHeaders["content-length"]
	require.False(t, ok)
}

func TestMagicEnabled(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)
	// Magic is enabled by default

	bodyContent := "test body content"
	err := test.SetRequestBody(bodyContent)
	require.NoError(t, err)

	// With magic enabled, content-length should be set automatically
	require.Equal(t, "17", test.RequestHeaders["content-length"])
}

func TestSetRequestBody_Nil(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	err := test.SetRequestBody(nil)
	require.NoError(t, err)
}

func TestSetRequestBody_EmptyString(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	err := test.SetRequestBody("")
	require.NoError(t, err)
}

func TestSetResponseBody_Nil(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithResponseBodyAccess(),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)

	err = test.SetResponseBody(nil)
	require.NoError(t, err)
}

func TestSetResponseBody_EmptyString(t *testing.T) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithResponseBodyAccess(),
	)
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)

	err = test.SetResponseBody("")
	require.NoError(t, err)
}

func TestBodyToString_StringArray(t *testing.T) {
	result := bodyToString([]string{"line1", "line2", "line3"})
	expected := "line1\r\nline2\r\nline3\r\n\r\n"
	require.Equal(t, expected, result)
}

func TestBodyToString_String(t *testing.T) {
	input := "simple string body"
	result := bodyToString(input)
	require.Equal(t, input, result)
}

func TestBodyToString_InvalidType(t *testing.T) {
	defer func() {
		require.NotNil(t, recover())
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
	require.NoError(t, err, "unexpected error")
	test := NewTest("test", waf)
	test.RequestURI = "/test"

	err = test.RunPhases()
	require.NoError(t, err)

	require.True(t, test.LogContains("Unique test message"))
	require.False(t, test.LogContains("Message not in log"))
}

func TestTransaction(t *testing.T) {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	test := NewTest("test", waf)

	tx := test.Transaction()
	require.NotNil(t, tx)
}
