// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Audit logs are currently disabled for tinygo

//go:build !tinygo

package testing

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/corazawaf/coraza/v3/internal/auditlog"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/seclang"
)

func TestAuditLogMessages(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)

	file, err := os.CreateTemp(t.TempDir(), "tmp.log")
	require.NoError(t, err)
	defer file.Close()
	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)
	err = parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine On
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogParts ABCDEFGHIJKZ
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,log,msg:'unconditional match'"
	`)
	require.NoError(t, err)
	defer os.Remove(file.Name())

	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	al := tx.AuditLog()
	require.Len(t, al.Messages(), 1)
	require.Equal(t, "unconditional match", al.Messages()[0].Message())
	tx.ProcessLogging()
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	var al2 auditlog.Log
	err = json.NewDecoder(file).Decode(&al2)
	require.NoError(t, err)
	require.Len(t, al2.Messages(), 1)
	require.Equal(t, "unconditional match", al2.Messages()[0].Message())
}

func TestAuditLogRelevantOnly(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine RelevantOnly
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogRelevantStatus 401
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,log,msg:'unconditional match'"
	`)
	require.NoError(t, err)

	file, err := os.CreateTemp(t.TempDir(), "tmp.log")
	require.NoError(t, err)
	defer file.Close()
	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	tx.ProcessLogging()
	var al2 auditlog.Log
	// this should fail, there should be no log
	err = json.NewDecoder(file).Decode(&al2)
	require.Error(t, err)
}

func TestAuditLogRelevantOnlyOk(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	file, err := os.CreateTemp(t.TempDir(), "tmp.log")
	require.NoError(t, err)
	defer file.Close()
	defer os.Remove(file.Name())
	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)
	err = parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine RelevantOnly
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogRelevantStatus ".*"
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,log,msg:'unconditional match'"
	`)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	tx.ProcessLogging()
	var al2 auditlog.Log
	// this should pass as it matches any status
	err = json.NewDecoder(file).Decode(&al2)
	require.NoError(t, err)
}

func TestAuditLogRelevantOnlyNoAuditlogNoRelevantStatus(t *testing.T) {
	// When a rule matches with noauditlog AND the response status does not match
	// SecAuditLogRelevantStatus, no audit log should be written.
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine RelevantOnly
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogRelevantStatus "^5"
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,noauditlog,msg:'unconditional match'"
	`)
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "tmp.log")
	require.NoError(t, err)
	defer file.Close()
	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	tx.ProcessLogging()
	var al2 auditlog.Log
	// Status is 200 (not 5xx), and no auditlog action → should not log
	err = json.NewDecoder(file).Decode(&al2)
	require.Error(t, err)
}

func TestAuditLogRelevantOnlyNoAuditlogButRelevantStatus(t *testing.T) {
	// When a rule matches with noauditlog BUT the response status matches
	// SecAuditLogRelevantStatus, the audit log should still be written (OR semantics).
	// Regression test for https://github.com/corazawaf/coraza/issues/1576
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine RelevantOnly
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogRelevantStatus ".*"
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,noauditlog,msg:'unconditional match'"
	`)
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "tmp.log")
	require.NoError(t, err)
	defer file.Close()
	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	tx.ProcessLogging()
	var al2 auditlog.Log
	// Status matches SecAuditLogRelevantStatus ".*" → should log despite noauditlog
	err = json.NewDecoder(file).Decode(&al2)
	require.NoError(t, err)
}

func TestAuditLogOnWithNoLog(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine On
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogParts ABCHIJKZ
		SecAuditLogRelevantStatus ".*"
		# auditlog tells that the transaction will have to log matches meant to be logged (not the ones with nolog)
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,nolog,msg:'nolog message'"
	`)
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "tmp.log")
	require.NoError(t, err)
	defer file.Close()
	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	tx.ProcessLogging()
	var al2 auditlog.Log
	// there should be no audit log because of nolog
	err = json.NewDecoder(file).Decode(&al2)
	if err == nil {
		require.Nil(t, al2.Messages())
	} else {
		require.NoError(t, err)
	}
}

func TestAuditLogOnNoLogAuditLog(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine On
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogParts ABCHIJKZ
		SecAuditLogRelevantStatus ".*"
		# auditlog tells that the transaction will have to log matches meant to be logged (not the ones with nolog)
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,nolog,auditlog,msg:'unconditional match'"
	`)
	require.NoError(t, err)
	// generate a random tmp file
	file, err := os.CreateTemp(t.TempDir(), "tmp.log")
	require.NoError(t, err)
	defer file.Close()
	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	tx.ProcessLogging()
	var al auditlog.Log
	err = json.NewDecoder(file).Decode(&al)
	require.NoError(t, err)
	require.Len(t, al.Messages(), 1)
	require.Equal(t, "unconditional match", al.Messages()[0].Message())
}

func TestAuditLogRequestMethodURIProtocol(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine On
		SecAuditLogFormat json
		SecAuditLogType serial
	`)
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "tmp.log")
	require.NoError(t, err)
	defer file.Close()
	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)
	tx := waf.NewTransaction()

	uri := "/some-url"
	method := "POST"
	proto := "HTTP/1.1"

	tx.ProcessURI(uri, method, proto)
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	tx.ProcessLogging()
	var al2 auditlog.Log
	err = json.NewDecoder(file).Decode(&al2)
	require.NoError(t, err)
	trans := al2.Transaction()
	require.NotNil(t, trans)
	req := trans.Request()
	require.NotNil(t, req)
	require.Equal(t, uri, req.URI())
	require.Equal(t, method, req.Method())
	require.Equal(t, proto, req.Protocol())
}

func TestAuditLogRequestBody(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine On
		SecAuditLogFormat json
		SecAuditLogType serial
		SecRequestBodyAccess On
	`)
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "tmp.log")
	require.NoError(t, err)
	defer file.Close()
	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)
	tx := waf.NewTransaction()
	params := "somepost=data"
	_, _, err = tx.ReadRequestBodyFrom(strings.NewReader(params))
	require.NoError(t, err)
	_, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	tx.ProcessLogging()
	var al2 auditlog.Log
	err = json.NewDecoder(file).Decode(&al2)
	require.NoError(t, err)
	trans := al2.Transaction()
	require.NotNil(t, trans)
	req := trans.Request()
	require.NotNil(t, req)
	require.Equal(t, params, req.Body())
}

// Arule expected to be logged (log and auditlog flags enabled) should
// print the error message in the audit log as part of the H section.
func TestAuditLogHFlag(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine On
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogParts AHZ
		SecAuditLogRelevantStatus ".*"
		# An audit log should contain messages section on H flag included
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,log,auditlog,msg:'expected rule message'"
	`)
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "tmp.log")
	require.NoError(t, err)
	defer file.Close()
	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	tx.ProcessLogging()
	var al auditlog.Log
	err = json.NewDecoder(file).Decode(&al)
	require.NoError(t, err)
	require.Len(t, al.Messages(), 1)
	type auditLogWithErrMesg interface{ ErrorMessage() string }
	alWithErrMsg, ok := al.Messages()[0].(auditLogWithErrMesg)
	require.True(t, ok, "Expected message to be of type auditLogWithErrMesg")
	expected := "expected rule message"
	require.Contains(t, alWithErrMsg.ErrorMessage(), expected)
}

func TestAuditLogWithKFlagWithoutHFlag(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine On
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogParts ABCKZ
		SecAuditLogRelevantStatus ".*"
		# auditlog should not contain error logs without H flag included
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,log,auditlog,msg:'unexpected logged message'"
	`)
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "tmp.log")
	require.NoError(t, err)
	defer file.Close()
	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	tx.ProcessLogging()
	var al auditlog.Log
	err = json.NewDecoder(file).Decode(&al)
	require.NoError(t, err)
	require.Len(t, al.Messages(), 1)
	type auditLogWithErrMesg interface{ ErrorMessage() string }
	alWithErrMsg, ok := al.Messages()[0].(auditLogWithErrMesg)
	require.True(t, ok, "Expected message to be of type auditLogWithErrMesg")
	notExpected := "unexpected logged message"
	require.NotContains(t, alWithErrMsg.ErrorMessage(), notExpected)
}
func TestAuditLogRelevantOnlyDetectionOnly(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine RelevantOnly
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogRelevantStatus "403"
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,deny,log,auditlog,msg:'expected rule message'"
	`)
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "tmp.log")
	require.NoError(t, err)
	defer file.Close()
	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	tx.ProcessLogging()
	var al auditlog.Log
	err = json.NewDecoder(file).Decode(&al)
	require.NoError(t, err)
	require.Len(t, al.Messages(), 1)
	type auditLogWithErrMesg interface{ ErrorMessage() string }
	alWithErrMsg, ok := al.Messages()[0].(auditLogWithErrMesg)
	require.True(t, ok, "Expected message to be of type auditLogWithErrMesg")
	expected := "expected rule message"
	require.Contains(t, alWithErrMsg.ErrorMessage(), expected)
}
