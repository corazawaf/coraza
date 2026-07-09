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
							Data: `{"test": 123, "test2": 456, "test3": [22, 44, 55], "test4": 3}`,
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

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "kabbohus",
		Description: "Test if truncated JSON request/response body work",
		Enabled:     true,
		Name:        "truncatedjsonyaml",
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
								1104,
								1010,
								1000,
								1011,
								1200,
								1201,
							},
							NonTriggeredRules: []int{
								103,
								1102,
								1103,
								1111,
								1202,
								1203,
							},
							Headers: map[string]string{
								"Content-Type": "application/json",
							},
							Data: `{"test": 123, "test2": 456, "test3": [22, 44, 55], "test4": 3}`,
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
SecRequestBodyLimitAction ProcessPartial
SecRequestBodyLimit 40
SecRule REQUEST_HEADERS:content-type "application/json" "id: 100, phase:1, pass, log, ctl:requestBodyProcessor=JSON"
SecRule RESPONSE_HEADERS:content-type "application/json" "id:1000, phase:3, pass, log, ctl:responseBodyProcessor=JSON"
SecRule REQBODY_PROCESSOR "JSON" "id: 101,phase:2,log,block"

# This is commented out because we want to check if body processor can work with partial JSON
# SecRule REQBODY_ERROR "!@eq 0" "id:1111, phase:2, log, block"

SecRule REQUEST_BODY "456" "id:103, phase:2, log"
SecRule ARGS:json.test "@eq 123" "id:1100, phase:2, log, block"
SecRule ARGS:json.test3.0 "@eq 22" "id:1101, phase:2, log, block"
SecRule ARGS:json.test3.1 "@eq 44" "id:1102, phase:2, log, block"
SecRule ARGS:json.test3.2 "@eq 55" "id:1103, phase:2, log, block"

# Both GET and POST can be matched for the same key
SecRule ARGS:json.test "@eq 456" "id:1104, phase:2, log, block"

SecRule ARGS:json.test3 "@eq 1" "id: 1010, phase:2, log, block"

# Check ARGS_POST
SecRule ARGS_POST:json.test "@eq 123" "id:1200, phase:2, log, block"
SecRule ARGS_POST:json.test3.0 "@eq 22" "id:1201, phase:2, log, block"
SecRule ARGS_POST:json.test3.1 "@eq 44" "id:1202, phase:2, log, block"
SecRule ARGS_POST:json.test3.2 "@eq 55" "id:1203, phase:2, log, block"

SecRule RESPONSE_ARGS:json.test4 "@eq 3" "id: 1011, phase:4, log, block"
`,
})
