// Copyright 2021 Juan Pablo Tosso
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

	engine "github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/loggers"
	"github.com/jptosso/coraza-waf/v2/types"
	utils "github.com/jptosso/coraza-waf/v2/utils/strings"
)

func Test_directiveSecAuditLog(t *testing.T) {
	w := engine.NewWaf()
	p, _ := NewParser(w)
	if err := p.FromString("SecWebAppId test123"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.WebAppID != "test123" {
		t.Error("failed to set SecWebAppId")
	}
	if err := p.FromString("SecUploadKeepFiles On"); err != nil {
		t.Error("failed to set parser from string")
	}
	if !w.UploadKeepFiles {
		t.Error("failed to set SecUploadKeepFiles")
	}
	if err := p.FromString("SecUploadFileMode 0700"); err != nil {
		t.Error("failed to set parser from string")
	}
	if err := p.FromString("SecUploadFileLimit 1000"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.UploadFileLimit != 1000 {
		t.Error("failed to set SecUploadFileLimit")
	}
	if err := p.FromString("SecUploadDir /tmp"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.UploadDir != "/tmp" {
		t.Error("failed to set SecUploadDir")
	}
	if err := p.FromString("SecTmpDir /tmp"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.TmpDir != "/tmp" {
		t.Error("failed to set SecTmpDir")
	}
	if err := p.FromString("SecSensorId test"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.SensorID != "test" {
		t.Error("failed to set SecSensorId")
	}
	if err := p.FromString("SecRuleEngine DetectionOnly"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.RuleEngine != types.RuleEngineDetectionOnly {
		t.Errorf("failed to set SecRuleEngine, got %s and expected %s", w.RuleEngine.String(), types.RuleEngineDetectionOnly.String())
	}
	if err := p.FromString(`SecAction "id:1,tag:test"`); err != nil {
		t.Error("failed to set parser from string")
	}
	if err := p.FromString("SecRuleRemoveByTag test"); err != nil {
		t.Error("failed to set parser from string")
	}
	if p.Waf.Rules.Count() != 0 {
		t.Error("Failed to remove rule with SecRuleRemoveByTag")
	}
	if err := p.FromString(`SecAction "id:1,msg:'test'"`); err != nil {
		t.Error("failed to set parser from string")
	}
	if err := p.FromString("SecRuleRemoveByMsg test"); err != nil {
		t.Error("failed to set parser from string")
	}
	if p.Waf.Rules.Count() != 0 {
		t.Error("Failed to remove rule with SecRuleRemoveByMsg")
	}
	if err := p.FromString(`SecAction "id:1"`); err != nil {
		t.Error("failed to set parser from string")
	}
	if err := p.FromString("SecRuleRemoveById 1"); err != nil {
		t.Error("failed to set parser from string")
	}
	if p.Waf.Rules.Count() != 0 {
		t.Error("Failed to remove rule with SecRuleRemoveById")
	}
	if err := p.FromString("SecResponseBodyMimeTypesClear"); err != nil {
		t.Error("failed to set parser from string")
	}
	if len(p.Waf.ResponseBodyMimeTypes) != 0 {
		t.Error("failed to set SecResponseBodyMimeTypesClear")
	}
	if err := p.FromString("SecResponseBodyMimeType text/html"); err != nil {
		t.Error("failed to set parser from string")
	}
	if p.Waf.ResponseBodyMimeTypes[0] != "text/html" {
		t.Error("failed to set SecResponseBodyMimeType")
	}
}

func TestDebugDirectives(t *testing.T) {
	waf := engine.NewWaf()
	tmpf, _ := ioutil.TempFile("/tmp", "*.log")
	tmp := tmpf.Name()
	p, _ := NewParser(waf)
	err := directiveSecDebugLog(waf, tmp)
	if err != nil {
		t.Error(err)
	}
	if err := directiveSecDebugLogLevel(waf, "5"); err != nil {
		t.Error(err)
	}
	p.Waf.Logger.Info("abc123")
	data, _ := os.ReadFile(tmp)
	if !strings.Contains(string(data), "abc123") {
		t.Error("failed to write info log")
	}
}

func TestSecAuditLogDirectivesDefaults(t *testing.T) {
	waf := engine.NewWaf()
	tmpf, err := ioutil.TempFile("/tmp", "*.log")
	if err != nil {
		t.Error(err)
	}
	if err := directiveSecAuditLog(waf, tmpf.Name()); err != nil {
		t.Error(err)
	}
	if err := directiveSecAuditLogDir(waf, "/tmp"); err != nil {
		t.Error(err)
	}
	if waf.AuditLogger() == nil {
		t.Error("Invalid audit logger (nil)")
		return
	}
	if err := waf.AuditLogger().Write(loggers.AuditLog{
		Parts: types.AuditLogParts("ABCDEFGHIJ"),
		Transaction: loggers.AuditTransaction{
			ID: "test-12345",
		},
	}); err != nil {
		t.Error(err)
	}
	data, err := ioutil.ReadFile(tmpf.Name())
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(string(data), "test-12345") {
		t.Error("failed to write audit log")
	}
}

func TestSecAuditLogDirectivesConcurrent(t *testing.T) {
	waf := engine.NewWaf()
	auditpath := "/tmp/"
	parser, _ := NewParser(waf)
	if err := parser.FromString(`
	SecAuditLog /tmp/audit.log
	SecAuditLogFormat json
	SecAuditLogType concurrent
	SecAuditLogDir /tmp
	`); err != nil {
		t.Error(err)
	}
	id := utils.SafeRandom(10)
	if waf.AuditLogger() == nil {
		t.Error("Invalid audit logger (nil)")
		return
	}
	if err := waf.AuditLogger().Write(loggers.AuditLog{
		Parts: types.AuditLogParts("ABCDEFGHIJKZ"),
		Transaction: loggers.AuditTransaction{
			ID: id,
		},
	}); err != nil {
		t.Error(err)
	}
	f, err := findFileContaining(auditpath, id)
	if err != nil {
		t.Error(err)
	}
	data, err := ioutil.ReadFile(f)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(string(data), id) {
		t.Error("failed to write audit log")
	}
	// we test it is a valid json
	var j map[string]interface{}
	if err := json.Unmarshal(data, &j); err != nil {
		t.Error(err)
	}
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
