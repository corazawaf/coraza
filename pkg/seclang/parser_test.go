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
	"github.com/jptosso/coraza-waf/pkg/engine"
	"strings"
	"testing"
)

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

	if waf.AuditLogFileMode != 777 {
		t.Error("Failed to set log file mode")
	}
	if waf.AuditLogDirMode != 777 {
		t.Error("Failed to set log file mode")
	}

	err = p.FromString("Unsupported 123")
	if err == nil {
		t.Error("Invalid directives shouldn't work")
	}
}
