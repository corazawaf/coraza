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
	"io/ioutil"
	"strings"
	"testing"

	engine "github.com/jptosso/coraza-waf"
	"github.com/jptosso/coraza-waf/utils"
)

func Test_directiveSecAuditLog(t *testing.T) {
	w := engine.NewWaf()
	p, _ := NewParser(w)
	if err := p.FromString("SecWebAppId test123"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.WebAppId != "test123" {
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
	//if w.UploadFileMode != 0700 {
	//	t.Error("Failed to set SecUploadFileMode")
	//}
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
	//"SecServerSignature":            directiveSecServerSignature,
	if err := p.FromString("SecSensorId test"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.SensorId != "test" {
		t.Error("failed to set SecSensorId")
	}
	if err := p.FromString("SecRuleEngine DetectionOnly"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.RuleEngine != engine.RULE_ENGINE_DETECTONLY {
		t.Error("failed to set SecRuleEngine")
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
	if err := p.FromString("SecUnicodeMap 20127"); err != nil {
		t.Error("failed to set parser from string")
	}
	if p.Waf.Unicode.Map != "20127" {
		t.Error("failed to set SecUnicodeMap")
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
	//"SecResponseBodyLimitAction":    directiveSecResponseBodyLimitAction,
	//"SecResponseBodyLimit":          directiveSecResponseBodyLimit,
	//"SecResponseBodyAccess":         directiveSecResponseBodyAccess,
	//"SecRequestBodyNoFilesLimit":    directiveSecRequestBodyNoFilesLimit,
	//"SecRequestBodyLimitAction":     directiveSecRequestBodyLimitAction,
	//"SecRequestBodyLimit":           directiveSecRequestBodyLimit,
	//"SecRequestBodyInMemoryLimit":   directiveSecRequestBodyInMemoryLimit,
	//"SecRequestBodyAccess":          directiveSecRequestBodyAccess,
	//"SecRemoteRulesFailAction":      directiveSecRemoteRulesFailAction,
	//"SecRemoteRules":                directiveSecRemoteRules,
	//"SecPcreMatchLimitRecursion":    directiveSecPcreMatchLimitRecursion,
	//"SecPcreMatchLimit":             directiveSecPcreMatchLimit,
	//"SecInterceptOnError":           directiveSecInterceptOnError,
	//"SecHttpBlKey":                  directiveSecHttpBlKey,
	//"SecHashParam":                  directiveSecHashParam,
	//"SecHashMethodRx":               directiveSecHashMethodRx,
	//"SecHashMethodPm":               directiveSecHashMethodPm,
	//"SecHashKey":                    directiveSecHashKey,
	//"SecHashEngine":                 directiveSecHashEngine,
	//"SecGsbLookupDb":                directiveSecGsbLookupDb,
	//"SecGeoLookupDb":                directiveSecGeoLookupDb,
	//"SecDefaultAction":              directiveSecDefaultAction,
	//"SecDataDir":                    directiveSecDataDir,
	//"SecContentInjection":           directiveSecContentInjection,
	//"SecConnWriteStateLimit":        directiveSecConnWriteStateLimit,
	//"SecConnReadStateLimit":         directiveSecConnReadStateLimit,
	//"SecConnEngine":                 directiveSecConnEngine,
	//"SecComponentSignature":         directiveSecComponentSignature,
	//"SecCollectionTimeout":          directiveSecCollectionTimeout,
	//"SecAuditLogRelevantStatus":     directiveSecAuditLogRelevantStatus,
	//"SecAuditLogParts":              directiveSecAuditLogParts,
	//"SecAuditLog":                   directiveSecAuditLog,
	//"SecAuditEngine":                directiveSecAuditEngine,
}

func TestDebugDirectives(t *testing.T) {
	waf := engine.NewWaf()
	tmpf, _ := ioutil.TempFile("/tmp", "*.log")
	tmp := tmpf.Name()
	p, _ := NewParser(waf)
	err := directiveSecDebugLog(p, tmp)
	if err != nil {
		t.Error(err)
	}
	p.Waf.Logger.Info("abc123")
	data, _ := utils.OpenFile(tmp, false, "")
	if !strings.Contains(string(data), "abc123") {
		t.Error("failed to write info log")
	}
	p.Waf.Logger.Debug("efgh123")
	data, _ = utils.OpenFile(tmp, false, "")
	if strings.Contains(string(data), "efgh123") {
		t.Error("debug data shouldn't be written")
	}
	if err := p.Waf.SetLogLevel(5); err != nil {
		t.Error("setting log level")
	}
	p.Waf.Logger.Debug("efgh123")
	data, _ = utils.OpenFile(tmp, false, "")
	if !strings.Contains(string(data), "efgh123") {
		t.Error("debug data wasn't writen")
	}
}
