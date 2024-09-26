// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/redwanghb/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the matchers works",
		Enabled:     true,
		Name:        "match.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "actions",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							DestAddr: "127.0.0.1",
							Method:   "GET",
							URI:      "/test.php?id=12345&pizza=pineapple",
							Headers: map[string]string{
								"content-type": "application/x-www-form-urlencoded",
								"test":         "123",
								"test2":        "456",
							},
						},

						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								26,
								28,
								30,
								35,
							},
							NonTriggeredRules: []int{
								1,
								2,
								40,
							},
						},
					},
				},
			},
		},
	},
	Rules: `
SecDebugLogLevel 9
SecRule SERVER_ADDR "! ^127" "id:1, phase:1, log"

SecRule SERVER_PORT "!" "id:2, phase:1, log"

SecRule ARGS "12345" "chain,block,id:26, log, phase: 2"
  SecRule MATCHED_VAR "12345" ""

SecRule ARGS_GET "12345" "chain,block, id:28, log, phase:2"
  SecRule MATCHED_VAR_NAME "ARGS_GET:id" ""

SecRule ARGS "12345" "chain,block, id:30, log, phase:2"
  SecRule ARGS "pineapple" "chain"
  SecRule MATCHED_VARS "12345" "" 
  #?


SecRule ARGS_GET "12345" "chain,block, id:35, log, phase:2"
  SecRule ARGS "pineapple" "chain"
  SecRule MATCHED_VARS_NAMES "ARGS_GET:id" "" 

# This rule should not be triggered because MATCHED_VARS_NAMES was reset by tx.resetAfterRule()
SecRule REQUEST_HEADERS "123" "chain,block, id:40, log, phase:2"
  SecRule REQUEST_HEADERS "456" "chain"
  SecRule MATCHED_VARS_NAMES "ARGS:id" ""
`,
})
