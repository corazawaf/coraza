// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

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
							TriggeredRules:    []int{100, 200, 250, 300},
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
SecRule ARGS:_msg_body "@rx Hi Martin," "id:200, phase:2,log"
SecRule MULTIPART_PART_HEADERS:_msg_body "Content-Disposition" "id:250, phase:2, log"
SecRule MULTIPART_PART_HEADERS "Content-Disposition" "id:300, phase:2, log"
SecRule REQBODY_ERROR "!@eq 0" \
  "id:'200002', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "MULTIPART_STRICT_ERROR rule triggered",
		Enabled:     true,
		Name:        "multipart_error.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "multipart error invalid 0x0E",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test.php?id=1",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
\x0EContent-Disposition: form-data; name="_msg_body"

The Content-Disposition header contains an invalid character (0x0E).
----0000--    
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{200002, 200003},
						},
					},
				},
			},
		},
		{
			Title: "multipart error invalid 0x20",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test.php",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-\x20Disposition: form-data; name="file"; filename="1.php"

0x20 character is expected to be the last invalid character before the valid range.
Therefore, the parser should fail and raise MULTIPART_STRICT_ERROR.
----0000--    
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{200002, 200003},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRule REQBODY_ERROR "!@eq 0" \
  "id:'200002', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}'"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
    "id:'200003',phase:2,t:none,log,deny,status:400, msg:'Multipart request body failed strict validation."
  `,
})
