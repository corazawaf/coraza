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
SecDebugLogLevel 5
SecRule SERVER_ADDR "! ^127" "id:1, phase:1, log"

SecRule SERVER_PORT "!" "id:2, phase:1, log"

SecRule ARGS "12345" "chain,block,id:26, log, phase: 2"
	SecRule MATCHED_VAR "12345" ""

SecRule ARGS "12345" "chain,block, id:28, log, phase:2"
  SecRule MATCHED_VAR_NAME "ARGS:id" ""      

SecRule ARGS "12345" "chain,block, id:30, log, phase:2"
  SecRule ARGS "pineapple" "chain"
  SecRule MATCHED_VARS "12345" "" 
  #?


SecRule ARGS "12345" "chain,block, id:35, log, phase:2"
  SecRule ARGS "pineapple" "chain"
  SecRule MATCHED_VARS_NAMES "ARGS:id" "" 

# This rule should not be triggered because MATCHED_VARS_NAMES was reset by tx.resetAfterRule()
SecRule REQUEST_HEADERS "123" "chain,block, id:40, log, phase:2"
  SecRule REQUEST_HEADERS "456" "chain"
  SecRule MATCHED_VARS_NAMES "ARGS:id" ""
`,
})
