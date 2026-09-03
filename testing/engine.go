// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	b64 "encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/variables"
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
		// i is the index of the empty line separator.
		// Skip the separator by joining from i+1.
		// If i is the last element (i+1 == len(spl)), spl[i+1:] is empty, which is correct.
		return t.SetRequestBody(strings.Join(spl[i+1:], "\r\n"))
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
	errors = append(errors, t.triggeredRulesCountErrors()...)
	errors = append(errors, t.logContainsCountErrors()...)
	errors = append(errors, t.variableErrors()...)
	errors = append(errors, t.auditLogErrors()...)

	return errors
}

// triggeredRulesCountErrors asserts the exact number of matches per rule id.
func (t *Test) triggeredRulesCountErrors() []string {
	if len(t.ExpectedOutput.TriggeredRulesCount) == 0 {
		return nil
	}
	counts := map[int]int{}
	for _, mr := range t.transaction.MatchedRules() {
		counts[mr.Rule().ID()]++
	}
	var errors []string
	for _, id := range sortedIntKeys(t.ExpectedOutput.TriggeredRulesCount) {
		want := t.ExpectedOutput.TriggeredRulesCount[id]
		if got := counts[id]; got != want {
			errors = append(errors, fmt.Sprintf("Expected rule '%d' to be triggered %d time(s), got %d", id, want, got))
		}
	}
	return errors
}

// logContainsCountErrors asserts how many error logs contain each substring.
func (t *Test) logContainsCountErrors() []string {
	if len(t.ExpectedOutput.LogContainsCount) == 0 {
		return nil
	}
	var errors []string
	for _, want := range sortedStringKeys(t.ExpectedOutput.LogContainsCount) {
		expected := t.ExpectedOutput.LogContainsCount[want]
		got := 0
		for _, mr := range t.transaction.MatchedRules() {
			got += strings.Count(mr.ErrorLog(), want)
		}
		if got != expected {
			errors = append(errors, fmt.Sprintf("Expected log to contain '%s' %d time(s), got %d", want, expected, got))
		}
	}
	return errors
}

// variableErrors asserts the value of transaction variables after the phases ran.
func (t *Test) variableErrors() []string {
	if len(t.ExpectedOutput.Variables) == 0 {
		return nil
	}
	tx, ok := t.transaction.(*corazawaf.Transaction)
	if !ok {
		return []string{"Variables assertions require the default transaction implementation"}
	}
	var errors []string
	for _, selector := range sortedStringKeys(t.ExpectedOutput.Variables) {
		want := t.ExpectedOutput.Variables[selector]
		got, err := variableValue(tx, selector)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Variable '%s': %s", selector, err))
			continue
		}
		if got != want {
			errors = append(errors, fmt.Sprintf("Variable '%s': expected: '%s', got: '%s'", selector, want, got))
		}
	}
	return errors
}

// variableValue resolves a seclang variable selector such as "TX:score" or
// "REQUEST_URI" against the transaction. A missing value resolves to "", so a
// test can assert a variable was never set.
func variableValue(tx *corazawaf.Transaction, selector string) (string, error) {
	name, key, _ := strings.Cut(selector, ":")
	if key == "" {
		name, key, _ = strings.Cut(selector, ".")
	}
	v, err := variables.Parse(strings.ToUpper(strings.TrimSpace(name)))
	if err != nil {
		return "", fmt.Errorf("unknown variable %q", name)
	}
	col := tx.Collection(v)
	if col == nil {
		return "", nil
	}
	if key == "" {
		if single, ok := col.(collection.Single); ok {
			return single.Get(), nil
		}
	}
	if keyed, ok := col.(collection.Keyed); ok {
		values := keyed.Get(key)
		if len(values) == 0 {
			return "", nil
		}
		return values[0], nil
	}
	if single, ok := col.(collection.Single); ok {
		return single.Get(), nil
	}
	if all := col.FindAll(); len(all) > 0 {
		return all[0].Value(), nil
	}
	return "", nil
}

// auditLogErrors asserts on the audit log built for the transaction.
func (t *Test) auditLogErrors() []string {
	expected := t.ExpectedOutput.AuditLog
	if expected == nil {
		return nil
	}
	tx, ok := t.transaction.(*corazawaf.Transaction)
	if !ok {
		return []string{"AuditLog assertions require the default transaction implementation"}
	}
	al := tx.AuditLog()
	var errors []string
	if expected.Parts != "" {
		got := make([]byte, 0, len(al.Parts()))
		for _, part := range al.Parts() {
			got = append(got, byte(part))
		}
		if string(got) != expected.Parts {
			errors = append(errors, fmt.Sprintf("AuditLog.Parts: expected: '%s', got: '%s'", expected.Parts, got))
		}
	}
	if expected.MessageCount != nil {
		if got := len(al.Messages()); got != *expected.MessageCount {
			errors = append(errors, fmt.Sprintf("AuditLog.MessageCount: expected: %d, got: %d", *expected.MessageCount, got))
		}
	}
	for _, want := range expected.MessagesContain {
		if !auditLogMessagesContain(al.Messages(), want) {
			errors = append(errors, fmt.Sprintf("Expected an audit log message to contain '%s'", want))
		}
	}
	for _, unwanted := range expected.NoMessagesContain {
		if auditLogMessagesContain(al.Messages(), unwanted) {
			errors = append(errors, fmt.Sprintf("Expected no audit log message to contain '%s'", unwanted))
		}
	}
	return errors
}

func auditLogMessagesContain(messages []plugintypes.AuditLogMessage, want string) bool {
	for _, m := range messages {
		if strings.Contains(m.Message(), want) {
			return true
		}
		if data := m.Data(); data != nil {
			if strings.Contains(data.Data(), want) || strings.Contains(data.Raw(), want) {
				return true
			}
		}
	}
	return false
}

// sortedIntKeys keeps assertion failures in a stable order across runs.
func sortedIntKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func sortedStringKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
