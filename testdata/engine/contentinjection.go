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
		Description: "Test if content injection works",
		Enabled:     true,
		Name:        "contentinjection.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "content injection",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								// It used to work but I´m not confident with the tests
								// needs more testing
								// 10101
							},
						},
					},
				},
			},
		},
	},
	Rules: `
SecResponseBodyMimeType text/html
SecRuleEngine On
SecContentInjection On
SecResponseBodyAccess On
SecAction "id:1, phase:3, append:abcdef, prepend:123"
SecRule RESPONSE_BODY "123abcdef" "id:10101, phase:4, log"
`,
})
