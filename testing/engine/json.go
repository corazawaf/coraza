// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the JSON request/response body work",
		Enabled:     true,
		Name:        "jsonyaml",
	},
	Tests: []profile.Test{
		{
			Title: "json",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php?json.test=456",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/json",
							},
							Data: `{"test":123, "test2": 456, "test3": [22, 44, 55]}`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								100,
								101,
								1100,
								1101,
								1102,
								1010,
								1000,
								1011,
							},
							NonTriggeredRules: []int{
								1111,
								103,
							},
							Headers: map[string]string{
								"Content-Type": "application/json",
							},
							Data: `{"test":123, "test2": 456, "test3": [22, 44, 55], "test4": 3}`,
						},
					},
				},
			},
		},
	},
	Rules: `
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType application/json
SecRule REQUEST_HEADERS:content-type "application/json" "id: 100, phase:1, pass, log, ctl:requestBodyProcessor=JSON"
SecRule RESPONSE_HEADERS:content-type "application/json" "id:1000, phase:3, pass, log, ctl:responseBodyProcessor=JSON"
SecRule REQBODY_PROCESSOR "JSON" "id: 101,phase:2,log,block"

SecRule REQBODY_ERROR "!@eq 0" "id:1111, phase:2, log, block"

SecRule REQUEST_BODY "456" "id:103, phase:2, log"
SecRule ARGS:json.test "@eq 123" "id:1100, phase:2, log, block"
SecRule ARGS:json.test3.2 "@eq 55" "id:1101, phase:2, log, block"

# Both GET and POST can be matched for the same key
SecRule ARGS:json.test "@eq 456" "id:1102, phase:2, log, block"

SecRule ARGS:json.test3 "@eq 3" "id: 1010, phase:2, log, block"
SecRule RESPONSE_ARGS:json.test4 "@eq 3" "id: 1011, phase:4, log, block"
`,
})
