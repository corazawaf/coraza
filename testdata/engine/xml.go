package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.ProfileMeta{
		Author:      "jptosso",
		Description: "Test if the body processors work",
		Enabled:     true,
		Name:        "postxml.yaml",
	},
	TinyGoDisable: true,
	Tests: []profile.ProfileTest{
		{
			Title: "postxml",
			Stages: []profile.ProfileStage{
				{
					Input: profile.ProfileStageInput{
						URI:    "/index.php?t1=aaa&t2=bbb&t3=ccc",
						Method: "POST",
						Headers: map[string]string{
							"content-type": "application/xml",
						},
						Data: `<?xml version="1.0"?><xml><Cs7QAF attribute_name="attribute_value">test123</Cs7QAF></xml>`,
					},
					Output: profile.ExpectedOutput{
						TriggeredRules:    []int{101, 102, 500},
						NonTriggeredRules: []int{103},
					},
				},
			},
		},
	},
	Rules: `
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:content-type "application/xml" "id: 100, phase:1, pass, log, ctl:requestBodyProcessor=XML"
SecRule REQBODY_PROCESSOR "XML" "id: 101,phase:2,log,block"
SecRule XML:/*|XML://@* "test123" "id:102, phase:2,log,block"
#REQUEST_BODY must be empty for XML body processor
SecRule XML:/* "test123" "id:500, log"
SecRule XML://@* "attribute_value" "id:501, log"
`,
})
