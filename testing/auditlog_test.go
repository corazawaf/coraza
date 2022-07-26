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
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/loggers"
	"github.com/corazawaf/coraza/v2/seclang"
	"github.com/stretchr/testify/require"
)

func TestAuditLogMessages(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := seclang.NewParser(waf)
	// generate a random tmp file
	file, err := os.CreateTemp("/tmp", "tmp*.log")
	require.NoError(t, err)

	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)

	err = parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine On
		SecAuditLogFormat json
		SecAuditLogType serial
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,log,msg:'unconditional match'"
	`)
	require.NoError(t, err)

	defer os.Remove(file.Name())
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test", "test")
	tx.ProcessRequestHeaders()
	al := tx.AuditLog()
	require.Len(t, al.Messages, 1, "unexpected number of messages")
	require.Equal(t, "unconditional match", al.Messages[0].Message, "unexpected message")

	tx.ProcessLogging()
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)

	var al2 loggers.AuditLog
	err = json.NewDecoder(file).Decode(&al2)
	require.NoError(t, err)
	require.Len(t, al2.Messages, 1, "unexpected number of messages")
	require.Equal(t, "unconditional match", al2.Messages[0].Message, "unexpected message")
}

func TestAuditLogRelevantOnly(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := seclang.NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine RelevantOnly
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogRelevantStatus 401
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,log,msg:'unconditional match'"
	`)
	require.NoError(t, err)

	// generate a random tmp file
	file, err := os.CreateTemp("/tmp", "tmp*.log")
	require.NoError(t, err)
	defer os.Remove(file.Name())

	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)

	tx.ProcessLogging()
	var al2 loggers.AuditLog
	// this should fail, there should be no log
	err = json.NewDecoder(file).Decode(&al2)
	require.Error(t, err)
}

func TestAuditLogRelevantOnlyOk(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := seclang.NewParser(waf)
	// generate a random tmp file
	file, err := os.CreateTemp("/tmp", "tmp*.log")
	require.NoError(t, err)
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
	tx.AddArgument("GET", "test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)

	tx.ProcessLogging()
	var al2 loggers.AuditLog
	// this should pass as it matches any status
	err = json.NewDecoder(file).Decode(&al2)
	require.NoError(t, err)
}

func TestAuditLogRelevantOnlyNoAuditlog(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := seclang.NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine RelevantOnly
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogRelevantStatus ".*"
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,noauditlog,msg:'unconditional match'"
	`)
	require.NoError(t, err)

	// generate a random tmp file
	file, err := os.CreateTemp("/tmp", "tmp*.log")
	require.NoError(t, err)
	defer os.Remove(file.Name())

	err = parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name()))
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	_, err = file.Seek(0, 0)
	require.NoError(t, err)

	tx.ProcessLogging()
	var al2 loggers.AuditLog
	// there should be no audit log because of noauditlog
	err = json.NewDecoder(file).Decode(&al2)
	require.Error(t, err, "there should be no audit log")
}
