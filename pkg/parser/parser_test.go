// Copyright 2020 Juan Pablo Tosso
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

package parser

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
	"testing"
	"strings"
)

func TestString(t *testing.T) {
	rule := `SecRule ARGS:/(.*?)/|REQUEST_HEADERS|!REQUEST_HEADERS:/X-(Coraza|\w+)/ "@rx (.*?)" "id:1, drop, phase: 1"`
	waf := &engine.Waf{}
	waf.Init()
	p := &Parser{}
	p.Init(waf)
	p.Evaluate(rule)

	if len(waf.Rules.GetRules()) != 1 {
		t.Error("Rule not created")
	}
	r := waf.Rules.GetRules()[0]
	if len(r.Actions) != 3 {
		t.Error("Failed to parse actions")
	}
	if len(r.Variables) != 2 {
		t.Error("Failed to parse variables, got", len(r.Variables))
	}
	if len(r.Variables[1].Exceptions) != 1 {
		t.Error("Failed to add exceptions to rule variable")
		return
	}
	if r.Variables[1].Exceptions[0] != `/x-(coraza|\w+)/` {
		t.Error("Invalid variable key for regex, got:", r.Variables[1].Exceptions[0])
	}
}

func TestString2(t *testing.T) {
	rule := `SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_HEADERS|XML:/*|XML://@* \
    "@rx (?:rO0ABQ|KztAAU|Cs7QAF)" \
    "id:944210,\
    phase:2,\
    block,\
    log,\
    msg:'Magic bytes Detected Base64 Encoded, probable java serialization in use',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    tag:'application-multi',\
    tag:'language-java',\
    tag:'platform-multi',\
    tag:'attack-rce',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/WEB_ATTACK/JAVA_INJECTION',\
    tag:'WASCTC/WASC-31',\
    tag:'OWASP_TOP_10/A1',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/2',\
    ver:'OWASP_CRS/3.2.0',\
    severity:'CRITICAL',\
    setvar:'tx.rce_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}'"`

	waf := &engine.Waf{}
	waf.Init()
	p := &Parser{}
	p.Init(waf)
	p.Evaluate(rule)

	if len(waf.Rules.GetRules()) != 1 {
		t.Error("Rule not created")
		return
	}
	r := waf.Rules.GetRules()[0]
	if len(r.Variables) != 8 {
		t.Error("Failed to parse variables, got", len(r.Variables))
		for _, v := range r.Variables {
			t.Error(v)
		}
	}
}

func TestString3(t *testing.T) {
	rule := `SecRule REQUEST_HEADERS:User-Agent "@rx (.*?)" "id:1, drop, phase: 1"`
	waf := &engine.Waf{}
	waf.Init()
	p := &Parser{}
	p.Init(waf)
	p.Evaluate(rule)

	if len(waf.Rules.GetRules()) != 1 {
		t.Error("Rule not created")
	}
	r := waf.Rules.GetRules()[0]
	if len(r.Actions) != 3 {
		t.Error("Failed to parse actions")
	}
	if len(r.Variables) != 1 && r.Variables[0].Key != "User-Agent" {
		t.Error("Failed to parse variables")
	}
}

func TestString4(t *testing.T) {
	rule := `SecRule REQUEST_HEADERS:User-Agent "@unconditionalMatch" "id:1, drop, phase: 1, t:none"`
	waf := &engine.Waf{}
	waf.Init()
	tx := waf.NewTransaction()
	p := &Parser{}
	p.Init(waf)
	p.Evaluate(rule)
	tx.ExecutePhase(1)
	if !tx.Disrupted {
		t.Error("Failed to execute rule")
	}
}

/*
* Directives
* TODO There should be an elegant way to separate them from the parser
 */

 func TestDirectives(t *testing.T) {
	data := []string{
		"SecAuditLogDirMode 777",
		"SecAuditLogFileMode 777",
		"SecAuditLogType Concurrent",
		"SecCollectionTimeout 1000",
		"SecContentInjection On",
		"SecHashEngine On",
		"SecHashKey nonworking",
		"SecHashParam nonworking",
		"SecHashMethodRx nonworking",
		"SecHashMethodPm nonworking",
		"SecGeoLookupDb /dev/null",
		"SecGsbLookupDb nonworking",
		"SecHttpBlKey nonworking",
		"SecInterceptOnError nonworking",
		"SecPcreMatchLimit nonworking",
		"SecPcreMatchLimitRecursion nonworking",
		"SecConnReadStateLimit nonworking",
		"SecSensorId sensor1",
		"SecConnWriteStateLimit nonworking",
		"SecRemoteRules https://raw.githubusercontent.com/jptosso/coraza-waf/master/examples/skipper/default.conf",
		"SecRulePerfTime nonworking",
		"SecStreamOutBodyInspection nonworking",
		"SecRuleUpdateTargetByTag nonworking",
		"SecRuleUpdateTargetByMsg nonworking",
		"SecRuleUpdateTargetById nonworking",
		"SecRuleUpdateActionById nonworking",
		"SecRuleScript nonworking",
		"SecUploadDir nonworking",
		"SecUploadFileLimit nonworking",
		"SecUploadFileMode nonworking",
		"SecUploadKeepFiles nonworking",
		"SecWebAppId test",
		"SecXmlExternalEntity nonworking",
		"SecRequestBodyLimit 10000",
		"SecResponseBodyAccess On",
		"SecComponentSignature signature",
		"SecErrorPage debug",
	}
	waf := &engine.Waf{}
	waf.Init()
	p := &Parser{}
	p.Init(waf)
	err := p.FromString(strings.Join(data, "\n"))
	if err != nil {
		t.Error("Failed to parse some directives")
	}

	if waf.AuditLogFileMode != 777{
		t.Error("Failed to set log file mode")
	}
	if waf.AuditLogDirMode != 777{
		t.Error("Failed to set log file mode")
	}

	err = p.FromString("Unsupported 123")
	if err == nil{
		t.Error("Invalid directives shouldn't work")
	}
}
