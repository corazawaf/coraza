// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// XML currently disabled on TinyGo
//go:build !tinygo

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the body processors work",
		Enabled:     true,
		Name:        "postxml.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "postxml",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
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

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "coraza",
		Description: "Test if the response XML body processor works",
		Enabled:     true,
		Name:        "response_xml.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "response_xml",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{200, 201, 202, 600, 601},
							NonTriggeredRules: []int{203},
							Headers: map[string]string{
								"content-type": "application/xml",
							},
							Data: `<?xml version="1.0"?><xml><Cs7QAF attribute_name="attribute_value">test123</Cs7QAF></xml>`,
						},
					},
				},
			},
		},
	},
	Rules: `
SecResponseBodyAccess On
SecResponseBodyMimeType application/xml
SecRule RESPONSE_HEADERS:content-type "application/xml" "id: 200, phase:3, pass, log, ctl:responseBodyProcessor=XML"
SecRule RES_BODY_PROCESSOR "XML" "id: 201, phase:4, log, pass"
SecRule RESPONSE_XML:/*|RESPONSE_XML://@* "test123" "id:202, phase:4, log, pass"
SecRule RESPONSE_XML:/* "test123" "id:600, phase:4, log, pass"
SecRule RESPONSE_XML://@* "attribute_value" "id:601, phase:4, log, pass"
SecRule RESPONSE_XML:/* "should_not_match" "id:203, phase:4, log, pass"
`,
})
