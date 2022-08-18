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
		Description: "Test if the default_actions work",
		Enabled:     true,
		Name:        "default_actions.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "default_actions",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/%FFindex.html?test=test1",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								1,
								2,
								3,
								4,
								5,
								6,
								7,
								8,
								9,
								10,
							},
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id:1, phase:1, pass"
SecAction "id:2, phase:2, pass"
SecAction "id:3, phase:3, pass"
SecAction "id:4, phase:4, pass"
SecAction "id:5, phase:5, pass"
SecAction "id:6, phase:1, pass"
SecAction "id:7, phase:2, pass"
SecAction "id:8, phase:3, pass"
SecAction "id:9, phase:4, pass"
SecAction "id:10, phase:5, pass"
`,
})
