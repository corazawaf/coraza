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
		Description: "Test if operators with files works",
		Enabled:     true,
		Name:        "operators_with_files.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "owf",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?ghi=cdf",
							Headers: map[string]string{
								"ghi":    "pineapple",
								"cookie": "ghi=cfg;def=ghi",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 3, 5, 10},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule ARGS_NAMES "@pmFromFile operators/op/pmFromFile-01.dat" "id:1,log"
SecRule REQUEST_COOKIES:def "@pmFromFile operators/op/pmFromFile-01.dat" "id:3,log"
SecRule REQUEST_COOKIES_NAMES "@pmFromFile operators/op/pmFromFile-01.dat" "id:5,log"
SecRule REQUEST_HEADERS_NAMES "@pmFromFile operators/op/pmFromFile-01.dat" "id:10,log"
`,
})
