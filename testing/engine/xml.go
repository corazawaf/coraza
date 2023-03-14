// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// XML currently disabled on TinyGo
//go:build !tinygo
// +build !tinygo

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
SecRule REQBODY_PROCESSOR "XML" "id: 101,phase:1,log,block"
SecRule XML:/*|XML://@* "test123" "id:102, phase:2,log,block"
#REQUEST_BODY must be empty for XML body processor
SecRule XML:/* "test123" "id:500, log"
SecRule XML://@* "attribute_value" "id:501, log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the XML body processors work",
		Enabled:     true,
		Name:        "postxml2.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "postxml2",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php?t1=aaa&t2=bbb&t3=ccc",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/xml",
							},
							Data: "<?xml version=\"1.0\"?><xml><element attribute_name=\"cnVudGltZQ\">element_value</element></xml>",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{101, 944300},
							NonTriggeredRules: []int{},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:content-type "application/xml" "id: 100, phase:1, pass, log, ctl:requestBodyProcessor=XML"
SecRule REQBODY_PROCESSOR "XML" "id: 101,phase:1,log,block"
SecRule XML:/*|XML://@* \
    "@rx (?:cnVudGltZQ|HJ1bnRpbWU|BydW50aW1l|cHJvY2Vzc2J1aWxkZXI|HByb2Nlc3NidWlsZGVy|Bwcm9jZXNzYnVpbGRlcg|Y2xvbmV0cmFuc2Zvcm1lcg|GNsb25ldHJhbnNmb3JtZXI|BjbG9uZXRyYW5zZm9ybWVy|Zm9yY2xvc3VyZQ|GZvcmNsb3N1cmU|Bmb3JjbG9zdXJl|aW5zdGFudGlhdGVmYWN0b3J5|Gluc3RhbnRpYXRlZmFjdG9yeQ|BpbnN0YW50aWF0ZWZhY3Rvcnk|aW5zdGFudGlhdGV0cmFuc2Zvcm1lcg|Gluc3RhbnRpYXRldHJhbnNmb3JtZXI|BpbnN0YW50aWF0ZXRyYW5zZm9ybWVy|aW52b2tlcnRyYW5zZm9ybWVy|Gludm9rZXJ0cmFuc2Zvcm1lcg|BpbnZva2VydHJhbnNmb3JtZXI|cHJvdG90eXBlY2xvbmVmYWN0b3J5|HByb3RvdHlwZWNsb25lZmFjdG9yeQ|Bwcm90b3R5cGVjbG9uZWZhY3Rvcnk|cHJvdG90eXBlc2VyaWFsaXphdGlvbmZhY3Rvcnk|HByb3RvdHlwZXNlcmlhbGl6YXRpb25mYWN0b3J5|Bwcm90b3R5cGVzZXJpYWxpemF0aW9uZmFjdG9yeQ|d2hpbGVjbG9zdXJl|HdoaWxlY2xvc3VyZQ|B3aGlsZWNsb3N1cmU)" \
    "id:944300,\
    phase:2"
`,
})
