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
		Author:      "airween",
		Description: "Test against multipart payloads",
		Enabled:     true,
		Name:        "multipart.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "multipart",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test.php?id=12345",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-Disposition: form-data; name="_msg_body"

Hi Martin,

this is the test message.

Regards,

--
airween
----0000--    
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{100},
							NonTriggeredRules: []int{150, 200002},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRequestBodyAccess On
SecRule ARGS_POST:_msg_body "Hi" "id:100, phase:2,log"
SecRule ARGS_GET:_msg_body "Hi" "id:150, phase:2,log"
SecRule REQBODY_ERROR "!@eq 0" \
  "id:'200002', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"
`,
})
