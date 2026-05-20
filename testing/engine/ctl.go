// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the ctl action works",
		Enabled:     true,
		Name:        "ctl.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "actions",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "POST",
							URI:    "/test.php?id=1234",
							Data:   "pineapple=pizza",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								1,
								4,
								100,
								103,
								105,
							},
							NonTriggeredRules: []int{
								2,
								3,
								5,
								6,
								7,
								444,
							},
						},
					},
				},
			},
		},
		{
			Title: "ruleRemoveTargetById whole collection",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "GET",
							URI:    "/test.php?foo=bar&baz=qux",
						},
						Output: profile.ExpectedOutput{
							// Rule 200 removes all ARGS_GET from rule 201, so rule 201 should not match
							NonTriggeredRules: []int{201},
							TriggeredRules:    []int{200},
						},
					},
				},
			},
		},
		{
			Title: "ruleRemoveTargetById regex key",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "GET",
							// json.0.desc and json.1.desc match the regex; they are the only args
							URI: "/api/jobs?json.0.desc=attack&json.1.desc=attack",
						},
						Output: profile.ExpectedOutput{
							// Rule 300 logs and removes ARGS_GET:/^json\.\d+\.desc$/ from rule 301.
							// Rule 301 would normally match the attack args but they are excluded by ctl.
							TriggeredRules:    []int{300},
							NonTriggeredRules: []int{301},
						},
					},
				},
			},
		},
		{
			Title: "ruleRemoveTargetById regex key (POST JSON body)",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "POST",
							URI:    "/api/jsonjobs",
							Headers: map[string]string{
								"Content-Type": "application/json",
							},
							// JSON array → ARGS_POST: json.0.desc=attack, json.1.desc=attack
							Data: `[{"desc": "attack"}, {"desc": "attack"}]`,
						},
						Output: profile.ExpectedOutput{
							// Rule 310 sets the JSON body processor.
							// Rule 311 removes ARGS_POST matching /^json\.\d+\.desc$/ from rule 312.
							// Rule 312 would normally match "attack" but must be suppressed.
							TriggeredRules:    []int{310, 311},
							NonTriggeredRules: []int{312},
						},
					},
				},
			},
		},
		{
			Title: "ruleRemoveTargetByTag regex key",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "GET",
							// json.0.desc and json.1.desc match the regex; rule 321 is tagged OWASP_CRS
							URI: "/api/tag-test?json.0.desc=attack&json.1.desc=attack",
						},
						Output: profile.ExpectedOutput{
							// Rule 320 removes ARGS_GET:/^json\.\d+\.desc$/ from all rules tagged OWASP_CRS.
							// Rule 321 (tagged OWASP_CRS) would normally match the attack args but must be suppressed.
							TriggeredRules:    []int{320},
							NonTriggeredRules: []int{321},
						},
					},
				},
			},
		},
		{
			Title: "ruleRemoveTargetByMsg regex key",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "GET",
							// json.0.desc and json.1.desc match the regex; rule 331 has msg:'web shell detection'
							URI: "/api/msg-test?json.0.desc=attack&json.1.desc=attack",
						},
						Output: profile.ExpectedOutput{
							// Rule 330 removes ARGS_GET:/^json\.\d+\.desc$/ from all rules with msg:'web shell detection'.
							// Rule 331 would normally match the attack args but must be suppressed.
							TriggeredRules:    []int{330},
							NonTriggeredRules: []int{331},
						},
					},
				},
			},
		},
		{
			Title: "ruleRemoveTargetById chain child",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "GET",
							URI:    "/api/chain-id?json.content=attack",
						},
						Output: profile.ExpectedOutput{
							// Rule 340 removes ARGS_GET:json.content from rule 341.
							// Rule 341 is a chain whose child inspects ARGS_GET; the exclusion must
							// propagate to the chain child.
							TriggeredRules:    []int{340},
							NonTriggeredRules: []int{341},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "GET",
							URI:    "/api/chain-id?other=attack",
						},
						Output: profile.ExpectedOutput{
							// Negative: ctl removes ARGS_GET:json.content only. ARGS_GET:other is
							// not excluded, so the chain child must still match.
							TriggeredRules: []int{340, 341},
						},
					},
				},
			},
		},
		{
			Title: "ruleRemoveTargetByMsg chain child",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "GET",
							URI:    "/api/chain-msg?json.content=attack",
						},
						Output: profile.ExpectedOutput{
							// Rule 360 removes ARGS_GET:json.content from all rules whose parent
							// has msg:'argument too long'. Rule 361 is a chain with that parent msg
							// whose child inspects ARGS_GET; the exclusion must propagate.
							TriggeredRules:    []int{360},
							NonTriggeredRules: []int{361},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "GET",
							URI:    "/api/chain-msg?other=attack",
						},
						Output: profile.ExpectedOutput{
							// Negative: only ARGS_GET:json.content is removed; chain child still fires on `other`.
							TriggeredRules: []int{360, 361},
						},
					},
				},
			},
		},
		{
			Title: "ruleRemoveTargetByTag chain child",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "GET",
							URI:    "/api/chain-tag?json.content=attack",
						},
						Output: profile.ExpectedOutput{
							// Rule 350 removes ARGS_GET:json.content from all rules tagged OWASP_CRS.
							// Rule 351 is a chain tagged OWASP_CRS whose child inspects ARGS_GET; the
							// exclusion must propagate to the chain child.
							TriggeredRules:    []int{350},
							NonTriggeredRules: []int{351},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "GET",
							URI:    "/api/chain-tag?other=attack",
						},
						Output: profile.ExpectedOutput{
							// Negative: only ARGS_GET:json.content is removed; chain child still fires on `other`.
							TriggeredRules: []int{350, 351},
						},
					},
				},
			},
		},
	},
	Rules: `
SecDebugLogLevel 9
SecRequestBodyAccess On
SecAction "id:1, phase:1, ctl:ruleRemoveByTag=test, \
	ctl:ruleRemoveById=444, \
	ctl:ruleRemoveByMsg=test, \
	ctl:ruleRemoveTargetById=5;ARGS_GET:id, \
	ctl:ruleRemoveTargetByTag=test-tag;ARGS_GET:id, \
	ctl:ruleRemoveTargetByMsg=sometest;ARGS_GET:id, \
	ctl:forceRequestBodyVariable=On, \
	log"
SecAction "id: 2, phase: 1, log, tag:test"
SecAction "id: 3, phase: 1, log, msg:'test'"

# this rule should match
SecRule ARGS_GET "1234" "id: 4, phase: 1, log"
# this rule shouldn't match because of the CTL
SecRule ARGS_GET "1234" "id: 5, phase: 1, log"

#shouldnt match
SecRule ARGS_GET "1234" "id: 6, phase: 1, log, tag:test-tag"
SecRule ARGS_GET "1234" "id: 7, phase: 1, log, msg:'sometest'"

# should match
SecRule REQBODY_PROCESSOR "URLENCODED" "id:100,log,phase:2"
SecRule REQUEST_BODY "pizza" "id:103,log,phase:2"
SecRule ARGS_POST:pineapple "pizza" "id:105,log,phase:2"

SecAction "id:444,phase:2,log"

# ruleRemoveTargetById whole collection test: removes all ARGS_GET from rule 201
SecAction "id:200,phase:1,ctl:ruleRemoveTargetById=201;ARGS_GET,log"
SecRule ARGS_GET "@rx ." "id:201, phase:1, log"

# ruleRemoveTargetById regex key test (GET):
# Rule 300 removes ARGS_GET matching /^json\.\d+\.desc$/ from rule 301.
# Matching args (json.0.desc, json.1.desc) must NOT trigger rule 301.
SecRule REQUEST_URI "@beginsWith /api/jobs" "id:300,phase:1,pass,log,ctl:ruleRemoveTargetById=301;ARGS_GET:/^json\.\d+\.desc$/"
SecRule ARGS_GET "@rx attack" "id:301,phase:1,log"

# ruleRemoveTargetById regex key test (POST JSON body):
# Rule 310 activates JSON body processor for application/json requests.
# Rule 311 removes ARGS_POST matching /^json\.\d+\.desc$/ from rule 312 when URI starts with /api/jsonjobs.
# JSON body [{"desc":"attack"},{"desc":"attack"}] → ARGS_POST: json.0.desc=attack, json.1.desc=attack.
# Rule 312 would normally match "attack" in ARGS_POST but must be suppressed by rule 311's CTL.
SecRule REQUEST_HEADERS:content-type "@beginsWith application/json" "id:310,phase:1,pass,log,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_URI "@beginsWith /api/jsonjobs" "id:311,phase:1,pass,log,ctl:ruleRemoveTargetById=312;ARGS_POST:/^json\.\d+\.desc$/"
SecRule ARGS_POST "@rx attack" "id:312,phase:2,log"

# ruleRemoveTargetByTag regex key test:
# Rule 320 removes ARGS_GET matching /^json\.\d+\.desc$/ from all rules tagged OWASP_CRS.
# Rule 321 is tagged OWASP_CRS and would normally match the attack args but must be suppressed.
SecRule REQUEST_URI "@beginsWith /api/tag-test" "id:320,phase:1,pass,log,ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS_GET:/^json\.\d+\.desc$/"
SecRule ARGS_GET "@rx attack" "id:321,phase:1,log,tag:OWASP_CRS"

# ruleRemoveTargetByMsg regex key test:
# Rule 330 removes ARGS_GET matching /^json\.\d+\.desc$/ from all rules with msg:'web shell detection'.
# Rule 331 has msg:'web shell detection' and would normally match the attack args but must be suppressed.
SecRule REQUEST_URI "@beginsWith /api/msg-test" "id:330,phase:1,pass,log,ctl:ruleRemoveTargetByMsg=web shell detection;ARGS_GET:/^json\.\d+\.desc$/"
SecRule ARGS_GET "@rx attack" "id:331,phase:1,log,msg:'web shell detection'"

# ruleRemoveTargetById chain child test:
# Rule 340 removes ARGS_GET:json.content from rule 341. Rule 341 is a chain whose
# CHILD inspects ARGS_GET. The exclusion must propagate to the chain child or the
# request will be blocked by the child despite the ctl removal (issue #1610).
SecRule REQUEST_URI "@beginsWith /api/chain-id" "id:340,phase:1,pass,log,ctl:ruleRemoveTargetById=341;ARGS_GET:json.content"
SecRule REQUEST_METHOD "@rx ^GET$" "id:341,phase:1,log,chain"
    SecRule ARGS_GET "@rx attack" ""

# ruleRemoveTargetByTag chain child test (mirrors the CRS WordPress plugin case):
# Rule 350 removes ARGS_GET:json.content from all rules tagged OWASP_CRS. Rule 351
# is a chain tagged OWASP_CRS whose CHILD inspects ARGS_GET.
SecRule REQUEST_URI "@beginsWith /api/chain-tag" "id:350,phase:1,pass,log,ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS_GET:json.content"
SecRule REQUEST_METHOD "@rx ^GET$" "id:351,phase:1,log,tag:OWASP_CRS,chain"
    SecRule ARGS_GET "@rx attack" ""

# ruleRemoveTargetByMsg chain child test:
# Rule 360 removes ARGS_GET:json.content from all rules with msg:'argument too long'.
# Rule 361 is a chain whose PARENT has that msg and whose CHILD inspects ARGS_GET.
SecRule REQUEST_URI "@beginsWith /api/chain-msg" "id:360,phase:1,pass,log,ctl:ruleRemoveTargetByMsg=argument too long;ARGS_GET:json.content"
SecRule REQUEST_METHOD "@rx ^GET$" "id:361,phase:1,log,msg:'argument too long',chain"
    SecRule ARGS_GET "@rx attack" ""
`,
})
