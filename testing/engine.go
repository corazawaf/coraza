// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	b64 "encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/testing/profile"
	"github.com/corazawaf/coraza/v3/types"
)

// Test represents a unique transaction within
// a WAF instance for a test case
type Test struct {
	// waf contains a waf instance pointer
	waf coraza.WAF
	// transaction contains the current transaction
	transaction types.Transaction
	magic       bool
	Name        string
	body        string

	// public variables
	// RequestAddress contains the address of the request
	RequestAddress string
	// RequestPort contains the port of the request
	RequestPort int
	// RequestURI contains the uri of the request
	RequestURI string
	// RequestMethod contains the method of the request
	RequestMethod string
	// RequestProtocol contains the protocol of the request
	RequestProtocol string
	// RequestHeaders contains the headers of the request
	RequestHeaders map[string]string
	// ResponseHeaders contains the headers of the response
	ResponseHeaders map[string]string
	// ResponseCode contains the response code of the response
	ResponseCode int
	// ResponseProtocol contains the protocol of the response
	ResponseProtocol string
	// ServerAddress contains the address of the server
	ServerAddress string
	// ServerPort contains the port of the server
	ServerPort int
	// Expected contains the expected result of the test
	ExpectedOutput profile.ExpectedOutput
}

// SetWAF sets the waf instance pointer
func (t *Test) SetWAF(waf coraza.WAF) {
	t.waf = waf
}

// DisableMagic disables the magic flag
// which auto sets content-type and content-length
func (t *Test) DisableMagic() {
	t.magic = false
}

// SetEncodedRequest reads a base64 encoded request
// and sets it as the current request
func (t *Test) SetEncodedRequest(request string) error {
	if request == "" {
		return nil
	}
	sDec, err := b64.StdEncoding.DecodeString(request)
	if err != nil {
		return err
	}
	return t.SetRawRequest(sDec)
}

// SetRawRequest reads a raw request
// and sets it as the current request
func (t *Test) SetRawRequest(request []byte) error {
	if len(request) == 0 {
		return nil
	}
	spl := strings.Split(string(request), "\r\n")
	if len(spl) == 0 || len(spl) == 1 {
		// lets try with \n
		spl = strings.Split(string(request), "\n")
		if len(spl) == 0 || len(spl) == 1 {
			return fmt.Errorf("invalid request")
		}
	}
	// parse request line
	reqLine := strings.Split(spl[0], " ")
	if len(reqLine) != 3 {
		return fmt.Errorf("invalid request line, got %v", reqLine)
	}
	t.RequestMethod = reqLine[0]
	t.RequestURI = reqLine[1]
	t.RequestProtocol = reqLine[2]
	// parse headers
	t.RequestHeaders = make(map[string]string)
	i := 1
	for ; i < len(spl); i++ {
		if spl[i] == "" {
			break
		}
		key, val, ok := strings.Cut(spl[i], ":")
		if !ok {
			return fmt.Errorf("invalid header")
		}
		t.RequestHeaders[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	// parse body
	if i < len(spl) {
		return t.SetRequestBody(strings.Join(spl[i:], "\r\n"))
	}

	return nil
}

// SetRequestBody sets the request body
func (t *Test) SetRequestBody(body any) error {
	if body == nil {
		return nil
	}
	data := bodyToString(body)

	lbody := len(data)
	if lbody == 0 {
		return nil
	}
	t.body = data
	if t.magic {
		t.RequestHeaders["content-length"] = strconv.Itoa(lbody)
	}
	if _, _, err := t.transaction.WriteRequestBody([]byte(data)); err != nil {
		return err
	}
	return nil
}

// SetResponseBody sets the request body
func (t *Test) SetResponseBody(body any) error {
	if body == nil {
		return nil
	}
	data := bodyToString(body)

	lbody := len(data)
	if lbody == 0 {
		return nil
	}
	if it, _, err := t.transaction.WriteResponseBody([]byte(data)); it != nil || err != nil {
		return err
	}
	return nil
}

// RunPhases runs the phases of the test from 1 to 5
func (t *Test) RunPhases() error {
	t.transaction.ProcessConnection(t.RequestAddress, t.RequestPort, t.ServerAddress, t.ServerPort)
	t.transaction.ProcessURI(t.RequestURI, t.RequestMethod, t.RequestProtocol)
	for k, v := range t.RequestHeaders {
		t.transaction.AddRequestHeader(k, v)
	}
	t.transaction.ProcessRequestHeaders()

	if _, err := t.transaction.ProcessRequestBody(); err != nil {
		return err
	}
	for k, v := range t.ResponseHeaders {
		t.transaction.AddResponseHeader(k, v)
	}

	t.transaction.ProcessResponseHeaders(t.ResponseCode, t.ResponseProtocol)

	if _, err := t.transaction.ProcessResponseBody(); err != nil {
		return err
	}

	t.transaction.ProcessLogging()
	return nil
}

// OutputInterruptionErrors returns a list of errors
// that occurred when comparing the interruption result
func (t *Test) OutputInterruptionErrors() []string {
	var errors []string

	// Check if interruption expectation matches actual state
	if t.ExpectedOutput.Interruption == nil && t.transaction.IsInterrupted() {
		errors = append(errors, fmt.Sprintf("Expected no interruption, but transaction was interrupted by rule %d with action '%s'",
			t.transaction.Interruption().RuleID, t.transaction.Interruption().Action))
		return errors
	}

	if t.ExpectedOutput.Interruption != nil && !t.transaction.IsInterrupted() {
		errors = append(errors, "Expected interruption, but transaction was not interrupted")
		return errors
	}

	// If we expect an interruption and got one, validate the details
	if t.ExpectedOutput.Interruption != nil && t.transaction.IsInterrupted() {
		if t.ExpectedOutput.Interruption.Action != t.transaction.Interruption().Action {
			errors = append(errors, fmt.Sprintf("Interruption.Action: expected: '%s', got: '%s'",
				t.ExpectedOutput.Interruption.Action, t.transaction.Interruption().Action))
		}

		if t.ExpectedOutput.Interruption.Status != t.transaction.Interruption().Status {
			errors = append(errors, fmt.Sprintf("Interruption.Status: expected: '%d', got: '%d'",
				t.ExpectedOutput.Interruption.Status, t.transaction.Interruption().Status))
		}

		if t.ExpectedOutput.Interruption.Data != t.transaction.Interruption().Data {
			errors = append(errors, fmt.Sprintf("Interruption.Data: expected: '%s', got: '%s'",
				t.ExpectedOutput.Interruption.Data, t.transaction.Interruption().Data))
		}

		if t.ExpectedOutput.Interruption.RuleID != t.transaction.Interruption().RuleID {
			errors = append(errors, fmt.Sprintf("Interruption.RuleID: expected: '%d', got: '%d'",
				t.ExpectedOutput.Interruption.RuleID, t.transaction.Interruption().RuleID))
		}
	}

	return errors
}

// OutputErrors returns a list of errors that occurred during
// the test when comparing log and rule ids
func (t *Test) OutputErrors() []string {
	var errors []string
	if lc := t.ExpectedOutput.LogContains; lc != "" {
		if !t.LogContains(lc) {
			errors = append(errors, fmt.Sprintf("Expected log to contain '%s'", lc))
		}
	}
	if lc := t.ExpectedOutput.NoLogContains; lc != "" {
		if t.LogContains(lc) {
			errors = append(errors, fmt.Sprintf("Expected log to not contain '%s'", lc))
		}
	}
	/*
		if rc := t.ExpectedOutput.Status; rc != 0 {
			// do nothing
		}*/
	if tr := t.ExpectedOutput.TriggeredRules; tr != nil {
		for _, rule := range tr {
			if !t.LogContains(fmt.Sprintf("id \"%d\"", rule)) {
				errors = append(errors, fmt.Sprintf("Expected rule '%d' to be triggered", rule))
			}
		}
	}
	if tr := t.ExpectedOutput.NonTriggeredRules; tr != nil {
		for _, rule := range tr {
			if t.LogContains(fmt.Sprintf("id \"%d\"", rule)) {
				errors = append(errors, fmt.Sprintf("Expected rule '%d' to not be triggered", rule))
			}
		}
	}

	return errors
}

// LogContains checks if the log contains a string
func (t *Test) LogContains(log string) bool {
	for _, mr := range t.transaction.MatchedRules() {
		if strings.Contains(mr.ErrorLog(), log) {
			return true
		}
	}
	return false
}

// Transaction returns the transaction
func (t *Test) Transaction() types.Transaction {
	return t.transaction
}

// Request returns the raw request
func (t *Test) Request() string {
	str := fmt.Sprintf("%s %s %s\r\n", t.RequestMethod, t.RequestURI, t.RequestProtocol)
	for k, v := range t.RequestHeaders {
		str += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	str += "\r\n"
	if t.body != "" {
		str += t.body
	}
	return str
}

// NewTest creates a new test with default properties
func NewTest(name string, waf coraza.WAF) *Test {
	t := &Test{
		Name:           name,
		transaction:    waf.NewTransaction(),
		RequestHeaders: map[string]string{},
		ResponseHeaders: map[string]string{
			"Content-Type": "text/html",
		},
		RequestMethod:   "GET",
		RequestProtocol: "HTTP/1.1",
		RequestURI:      "/",
		RequestAddress:  "127.0.0.1",
		RequestPort:     80,
		magic:           true,
	}
	t.SetWAF(waf)
	return t
}

func bodyToString(iface any) string {
	data := ""
	switch v := iface.(type) {
	case []string:
		for i := range v {
			data += fmt.Sprintf("%s\r\n", v[i])
		}
		data += "\r\n"
	case string:
		data = v
	default:
		panic("Error: bodyToString() only accepts slices and strings")
	}
	return data
}
