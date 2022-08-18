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
		Description: "Test if the headers parsers work",
		Enabled:     true,
		Name:        "headers_parser.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "envs",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "GET",
							Headers: map[string]string{
								"test":              "456",
								"Transfer-Encoding": "chunked",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 5, 920171},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule REQUEST_HEADERS:test "456" "phase:1,t:none,log,id:1,msg:'test'"
SecRule REQUEST_HEADERS_NAMES "test" "log,id:5"

SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "id:920171,phase:1, log,chain"
  SecRule &REQUEST_HEADERS:Transfer-Encoding "!@eq 0" ""
`,
})
