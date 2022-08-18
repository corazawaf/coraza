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
		Description: "Test if the transformations work",
		Enabled:     true,
		Name:        "transformations.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "transformations",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/unittests@coreruleset.org\"%20sleep(10.to_i)%20",
							Headers: map[string]string{
								"test":  "1234",
								"test2": "456",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{777, 778, 942101},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule REQUEST_HEADERS:test "81dc9bdb52d04dc20036dbd8313ed055" "id:777, phase:1, log, multiMatch, t:none, t:md5, t:hexEncode"
SecRule REQUEST_HEADERS:test2 "@eq 32" "id:778, phase:1, log, t:none, t:md5, t:hexEncode, t:length"

SecRule REQUEST_BASENAME "@gt 10" "id:942101,phase:1,block,capture,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,t:length, log"
`,
})
