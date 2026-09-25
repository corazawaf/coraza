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

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "victors",
		Description: "XML file parts are reachable through XML targets when SecRequestBodyMultipartXMLParts is On",
		Enabled:     true,
		Name:        "multipart_xml_parts.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "xml file part is parsed into the XML collection",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/upload.php",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							// The payload is entity-encoded on the wire, as a
							// well-formed XML document carrying it would be. It is
							// only visible to @detectXSS once the part has been
							// tokenized.
							Data: "----0000\r\n" +
								"Content-Disposition: form-data; name=\"file\"; filename=\"payload.xml\"\r\n" +
								"Content-Type: application/octet-stream\r\n" +
								"\r\n" +
								"<?xml version=\"1.0\"?><r a=\"&lt;img src=x onerror=alert(1)&gt;\">&lt;script&gt;alert(1)&lt;/script&gt;</r>\r\n" +
								"----0000--\r\n",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{500, 501, 502, 503},
						},
					},
				},
			},
		},
		{
			Title: "non-xml file part contributes nothing to the XML collection",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/upload.php",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: "----0000\r\n" +
								"Content-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\n" +
								"Content-Type: text/plain\r\n" +
								"\r\n" +
								"just a log line\r\n" +
								"----0000--\r\n",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{503},
							NonTriggeredRules: []int{500, 501, 502},
						},
					},
				},
			},
		},
		{
			Title: "benign xml file part does not trigger the XSS rule",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/upload.php",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							// The XML declaration and tag syntax are consumed as
							// structure, so they never reach @detectXSS. Feeding
							// the raw bytes to it instead would match here.
							Data: "----0000\r\n" +
								"Content-Disposition: form-data; name=\"file\"; filename=\"report.xml\"\r\n" +
								"Content-Type: application/xml\r\n" +
								"\r\n" +
								"<?xml version=\"1.0\"?><report><title>quarterly figures</title></report>\r\n" +
								"----0000--\r\n",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{500, 503},
							NonTriggeredRules: []int{501, 502},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRequestBodyAccess On
SecRequestBodyMultipartXMLParts On
SecRule XML:/* "@rx ." "id:500, phase:2, log, pass"
SecRule XML:/* "@detectXSS" "id:501, phase:2, t:none, t:htmlEntityDecode, log, pass"
SecRule XML://@* "@detectXSS" "id:502, phase:2, t:none, t:htmlEntityDecode, log, pass"
SecRule FILES "@rx ." "id:503, phase:2, log, pass"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "victors",
		Description: "XML file parts stay invisible while SecRequestBodyMultipartXMLParts is Off",
		Enabled:     true,
		Name:        "multipart_xml_parts_disabled.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "default configuration does not expose file part content",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/upload.php",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: "----0000\r\n" +
								"Content-Disposition: form-data; name=\"file\"; filename=\"payload.xml\"\r\n" +
								"Content-Type: application/xml\r\n" +
								"\r\n" +
								"<?xml version=\"1.0\"?><r>&lt;script&gt;alert(1)&lt;/script&gt;</r>\r\n" +
								"----0000--\r\n",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{503},
							NonTriggeredRules: []int{500, 501},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRequestBodyAccess On
SecRule XML:/* "@rx ." "id:500, phase:2, log, pass"
SecRule XML:/* "@detectXSS" "id:501, phase:2, t:none, t:htmlEntityDecode, log, pass"
SecRule FILES "@rx ." "id:503, phase:2, log, pass"
`,
})
