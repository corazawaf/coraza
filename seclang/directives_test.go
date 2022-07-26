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

package seclang

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/loggers"
	"github.com/corazawaf/coraza/v2/types"
	utils "github.com/corazawaf/coraza/v2/utils/strings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NonImplementedDirective(t *testing.T) {
	rules := []string{
		`SecSensorId WAFSensor01`,
		`SecConnReadStateLimit 50 "!@ipMatch 127.0.0.1"`,
		`SecPcreMatchLimit 1500`,
		`SecPcreMatchLimitRecursion 1500`,
		`SecHttpBlKey whdkfieyhtnf`,
		`SecHashMethodRx HashHref "product_info|list_product"`,
		`SecHashMethodPm HashHref“product_info list_product”`,
		`SecHashParam "hmac"`,
		`SecHashKey "this_is_my_key" KeyOnly`,
		`SecHashEngine On`,
	}
	w := coraza.NewWaf()
	p, _ := NewParser(w)
	for _, rule := range rules {
		t.Run(rule, func(t *testing.T) {
			err := p.FromString(rule)
			assert.NoErrorf(t, err, "failed to set directive")
		})
	}
}

func Test_directive(t *testing.T) {
	w := coraza.NewWaf()
	p, _ := NewParser(w)

	err := p.FromString("SecWebAppId test123")
	require.NoError(t, err, "failed to set parser from string")
	require.Equal(t, "test123", w.WebAppID, "failed to set SecWebAppId")

	err = p.FromString("SecUploadKeepFiles On")
	require.NoError(t, err, "failed to set parser from string")
	require.True(t, w.UploadKeepFiles, "failed to set SecUploadKeepFiles")

	err = p.FromString("SecUploadFileMode 0700")
	require.NoError(t, err, "failed to set parser from string")

	err = p.FromString("SecUploadFileLimit 1000")
	require.NoError(t, err, "failed to set parser from string")
	require.Equal(t, 1000, w.UploadFileLimit, "failed to set SecUploadFileLimit")

	err = p.FromString("SecUploadDir /tmp")
	require.NoError(t, err, "failed to set parser from string")
	require.Equal(t, "/tmp", w.UploadDir, "failed to set SecUploadDir")

	err = p.FromString("SecTmpDir /tmp")
	require.NoError(t, err, "failed to set parser from string")
	require.Equal(t, "/tmp", w.TmpDir, "failed to set SecTmpDir")

	err = p.FromString("SecSensorId test")
	require.NoError(t, err, "failed to set parser from string")
	require.Equal(t, "test", w.SensorID, "failed to set SecSensorId")

	err = p.FromString("SecRuleEngine DetectionOnly")
	require.NoError(t, err, "failed to set parser from string")
	require.Equal(t, types.RuleEngineDetectionOnly, w.RuleEngine, "failed to set SecRuleEngine")

	err = p.FromString(`SecAction "id:1,tag:test"`)
	require.NoError(t, err, "failed to set parser from string")

	err = p.FromString("SecRuleRemoveByTag test")
	require.NoError(t, err, "failed to set parser from string")
	require.Zero(t, p.options.Waf.Rules.Count(), "failed to remove rule with SecRuleRemoveByTag")

	err = p.FromString(`SecAction "id:1,msg:'test'"`)
	require.NoError(t, err, "failed to set parser from string")

	err = p.FromString("SecRuleRemoveByMsg test")
	require.NoError(t, err, "failed to set parser from string")

	require.Zero(t, p.options.Waf.Rules.Count(), "Failed to remove rule with SecRuleRemoveByMsg")

	err = p.FromString(`SecAction "id:1"`)
	require.NoError(t, err, "failed to set parser from string")

	err = p.FromString("SecRuleRemoveById 1")
	require.NoError(t, err, "failed to set parser from string")

	require.Zero(t, p.options.Waf.Rules.Count(), "failed to remove rule with SecRuleRemoveById")

	err = p.FromString("SecResponseBodyMimeTypesClear")
	require.NoError(t, err, "failed to set parser from string")
	require.Empty(t, p.options.Waf.ResponseBodyMimeTypes, "failed to set SecResponseBodyMimeTypesClear")

	err = p.FromString("SecResponseBodyMimeType text/html")
	require.NoError(t, err, "failed to set parser from string")
	require.Equal(t, "text/html", p.options.Waf.ResponseBodyMimeTypes[0], "failed to set SecResponseBodyMimeType")

	err = p.FromString(`SecServerSignature "Microsoft-IIS/6.0"`)
	require.NoError(t, err, "failed to set directive: SecServerSignature")

	err = p.FromString(`SecRequestBodyInMemoryLimit 131072`)
	require.NoError(t, err, "failed to set directive: SecRequestBodyInMemoryLimit")

	err = p.FromString(`SecRemoteRulesFailAction Abort`)
	require.NoError(t, err, "failed to set directive: SecRemoteRulesFailAction")
}

func TestDebugDirectives(t *testing.T) {
	waf := coraza.NewWaf()
	tmpf, _ := ioutil.TempFile("/tmp", "*.log")
	tmp := tmpf.Name()
	p, _ := NewParser(waf)
	err := directiveSecDebugLog(&DirectiveOptions{
		Waf:  waf,
		Opts: tmp,
	})
	require.NoError(t, err)

	err = directiveSecDebugLogLevel(&DirectiveOptions{
		Waf:  waf,
		Opts: "5",
	})
	require.NoError(t, err)

	p.options.Waf.Logger.Info("abc123")
	data, _ := os.ReadFile(tmp)
	require.Contains(t, string(data), "abc123", "failed to write info log")
}

func TestSecAuditLogDirectivesConcurrent(t *testing.T) {
	waf := coraza.NewWaf()
	auditpath := "/tmp/"
	parser, _ := NewParser(waf)
	err := parser.FromString(`
	SecAuditLog /tmp/audit.log
	SecAuditLogFormat json
	SecAuditLogDir /tmp
	SecAuditLogDirMode 0777
	SecAuditLogFileMode 0777
	SecAuditLogType concurrent
	`)
	require.NoError(t, err)

	id := utils.SafeRandom(10)
	require.NotNil(t, waf.AuditLogWriter, "failed to create audit logger")

	err = waf.AuditLogWriter.Write(&loggers.AuditLog{
		Parts: types.AuditLogParts("ABCDEFGHIJKZ"),
		Transaction: loggers.AuditTransaction{
			ID: id,
		},
	})
	require.NoError(t, err)

	f, err := findFileContaining(auditpath, id)
	require.NoError(t, err)

	data, err := ioutil.ReadFile(f)
	require.NoError(t, err)
	require.Contains(t, string(data), id, "failed to write audit log")

	// we test it is a valid json
	var j map[string]interface{}
	err = json.Unmarshal(data, &j)
	require.NoError(t, err)
}

func TestSecRuleUpdateTargetBy(t *testing.T) {
	waf := coraza.NewWaf()
	rule, err := ParseRule(RuleOptions{
		Data:         "REQUEST_URI \"^/test\" \"id:181,tag:test\"",
		Waf:          waf,
		WithOperator: true,
	})
	require.NoError(t, err)

	err = waf.Rules.Add(rule)
	require.NoError(t, err)
	require.Equal(t, 1, waf.Rules.Count(), "failed to add rule")

	err = directiveSecRuleUpdateTargetByID(&DirectiveOptions{
		Waf:  waf,
		Opts: "181 \"REQUEST_HEADERS\"",
	})
	require.NoError(t, err)
}

// Find a file by name recursively containing some string
func findFileContaining(path string, search string) (string, error) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return "", err
	}
	for _, file := range files {
		if file.IsDir() {
			fullpath := path + "/" + file.Name()
			file, err := findFileContaining(fullpath, search)
			if err != nil {
				return "", err
			}
			if file != "" {
				return file, nil
			}
		} else if strings.Contains(file.Name(), search) {
			return path + "/" + file.Name(), nil
		}
	}
	return "", nil
}

func TestInvalidBooleanForDirectives(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	err := p.FromString("SecIgnoreRuleCompilationErrors sure")
	require.Error(t, err, "failed to error on invalid boolean")
}

func TestInvalidRulesWithIgnoredErrors(t *testing.T) {
	directives := `
	SecRule REQUEST_URI "@no_op ^/test" "id:181,tag:test"
	SecRule REQUEST_URI "@no_op ^/test" "id:200,tag:test,invalid:5"
	SecRule REQUEST_URI "@rx ^/test" "id:181,tag:repeated-id"
	`
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)

	err := p.FromString("secignorerulecompilationerrors On\n" + directives)
	require.NoError(t, err)

	waf = coraza.NewWaf()
	p, _ = NewParser(waf)

	err = p.FromString(directives)
	require.Error(t, err, "failed to error on invalid rule")
}
