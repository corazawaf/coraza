package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.ProfileMeta{
		Author:      "jptosso",
		Description: "Test if the json request body work",
		Enabled:     true,
		Name:        "jsonyaml",
	},
	Tests: []profile.ProfileTest{
		{
			Title: "json",
			Stages: []profile.ProfileStage{
				{
					Input: profile.ProfileStageInput{
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
							1010,
						},
						NonTriggeredRules: []int{
							1111,
							1102,
							103,
						},
					},
				},
			},
		},
	},
	Rules: `
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:content-type "application/json" "id: 100, phase:1, pass, log, ctl:requestBodyProcessor=JSON"
SecRule REQBODY_PROCESSOR "JSON" "id: 101,phase:2,log,block"

SecRule REQBODY_ERROR "!@eq 0" "id:1111, phase:2, log, block"

SecRule REQUEST_BODY "456" "id:103, phase:2, log"
SecRule ARGS:json.test "@eq 123" "id:1100, phase:2, log, block"
SecRule ARGS:json.test3.2 "@eq 55" "id:1101, phase:2, log, block"

# We test for some vulnerability
SecRule ARGS:json.test "@eq 456" "id:1102, phase:2, log, block"

SecRule ARGS:json.test3 "@eq 3" "id: 1010, phase:2, log, block"
`,
})
