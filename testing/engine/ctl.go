// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
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
`,
})
