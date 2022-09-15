// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the variables work",
		Enabled:     true,
		Name:        "variables.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "variables",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php?t1=aaa&t2=bbb&t3=ccc&a=test&jsessionid=74B0CB414BD77D17B5680A6386EF1666",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/x-www-form-urlencoded",
								"CookIe":       "phpmyadminphp=test",
								"user-agent":   "<ModSecurity CRS 3 Tests",
							},
							Data: `pineapple=123&file=cat+/etc/\passw\d`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								1,
								1234,
								// 2,
								15,
								110,
								130,
								200,
								300,
								400,
								10,
								500,
								600,
								700,
								100,
								1000,
								// 1500,
								123123,
								9123,
								99999,
							},
							NonTriggeredRules: []int{
								800,
								900,
								1100,
								920274,
								9124,
							},
							LogContains: `id "1234"`,
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule REQBODY_PROCESSOR "" "id: 10, log"
SecRequestBodyAccess On
SecRule ARGS:/^t1$/ "aaa" "id:1,phase:1,block,log"
SecRule &ARGS_GET:/t.*/ "@gt 2" "id: 1234, phase:1, block, log, setenv:test=some-secret"
# TODO
#SecRule &ARGS_GET|!ARGS_GET:/.*/ "@eq 0" "id: 1500, phase:1, block, log"
SecRule REQUEST_METHOD "POST" "id:15, log"
SecAction "id:100,log,setvar:'tx.test=%{REQUEST_METHOD}'"
SecRule TX:test "POST" "id:110,log"

SecAction "id:130,setvar:'tx.allowed_methods=GET HEAD OPTIONS'"
SecRule REQUEST_METHOD "!@within %{tx.allowed_methods}" "id:200,log"

SecRule REQUEST_COOKIES:pHpMyAdmInPhp "test" "id:300,phase:1,block,log"
SecRule ARGS_GET_NAMES "t1" "id:400,log"

SecRule ARGS_NAMES "jsessionid" "id: 500, log, phase:2"
SecRule ARGS_NAMES "pineapple" "id: 600, log, phase:2"
SecRule ARGS "(?:^|[^\x5c\x5c])\x5c\x5c[cdeghijklmpqwxyz123456789]" "id:700,log,phase:2"

SecRule ARGS|!ARGS:t1 "aaa" "id:800,log,phase:1"

SecRule ARGS|!ARGS:/t.*/ "aaa" "id:900,log,phase:1"
SecRule ARGS|!ARGS:/js.*/ "bbb" "id:1000,log,phase:1"
SecRule ARGS|!ARGS:/js.*/ "74B0CB414BD77D17B5680A6386EF1666" "id:1100,log,phase:1"

SecRule REQUEST_HEADERS|!REQUEST_HEADERS:User-Agent|!REQUEST_HEADERS:Referer|!REQUEST_HEADERS:Cookie|!REQUEST_HEADERS:Sec-Fetch-User|!REQUEST_HEADERS:Sec-CH-UA-Mobile \
  "@validateByteRange 32,34,38,42-59,61,65-90,95,97-122" "id:920274,phase:1,log,t:none,t:urlDecodeUni"

SecRule REQUEST_METHOD "^.*$" "capture,id:123123,phase:1,t:length,log,setvar:'tx.testuru=%{tx.0}',chain"
  SecRule TX:testuru "@eq 4" ""

SecRule ARGS:t1 "bbb" "id:9123,phase:1,log"
SecRuleUpdateTargetById 9123 "ARGS:t2"

SecRule ARGS "bbb" "id:9124,phase:1,log"
SecRuleUpdateTargetById 9124 "!ARGS:t2"

SecAction "id: 99999, log, msg:'%{env.test}'"
`,
})
