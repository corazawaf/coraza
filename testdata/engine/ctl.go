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
SecDebugLogLevel 5
SecRequestBodyAccess On
SecAction "id:1, phase:1, ctl:ruleRemoveByTag=test, \
	ctl:ruleRemoveById=444, \
	ctl:ruleRemoveByMsg=test, \
	ctl:ruleRemoveTargetById=5;ARGS:id, \
	ctl:ruleRemoveTargetByTag=test-tag;ARGS:id, \
	ctl:ruleRemoveTargetByMsg=sometest;ARGS:id, \
	ctl:forceRequestBodyVariable=On, \
	log"
SecAction "id: 2, phase: 1, log, tag:test"
SecAction "id: 3, phase: 1, log, msg:'test'"

# this rule should match
SecRule ARGS "1234" "id: 4, phase: 1, log"
# this rule shouldn't match because of the CTL
SecRule ARGS "1234" "id: 5, phase: 1, log"

#shouldnt match
SecRule ARGS "1234" "id: 6, phase: 1, log, tag:test-tag"
SecRule ARGS "1234" "id: 7, phase: 1, log, msg:'sometest'"

# should match
SecRule REQBODY_PROCESSOR "URLENCODED" "id:100,log,phase:2"
SecRule REQUEST_BODY "pizza" "id:103,log,phase:2"
SecRule ARGS:pineapple "pizza" "id:105,log,phase:2"

SecAction "id:444,phase:2,log"
`,
})
