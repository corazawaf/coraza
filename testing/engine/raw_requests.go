// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

// These cases cover the request input forms of the harness itself:
// raw_request, encoded_request and stop_magic. They are exercised the same way
// as everything else in testing/, by running a real transaction through them,
// rather than by asserting on the harness internals.
var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "coraza",
		Description: "Request input forms: raw, base64 encoded and without magic headers",
		Enabled:     true,
		Name:        "raw_requests.yaml",
	},
	Rules: `
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_METHOD "@streq POST" "id:1,phase:1,pass,log"
SecRule REQUEST_URI "@streq /raw?a=1" "id:2,phase:1,pass,log"
SecRule REQUEST_HEADERS:x-test "@streq raw-value" "id:3,phase:1,pass,log"
SecRule ARGS_POST:hello "@streq world" "id:4,phase:2,pass,log"
SecRule &REQUEST_HEADERS:content-length "@eq 0" "id:5,phase:1,pass,log"
`,
	Tests: []profile.Test{
		{
			Title: "a raw request feeds the method, uri, headers and body",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							RawRequest: []byte("POST /raw?a=1 HTTP/1.1\r\n" +
								"Host: www.example.com\r\n" +
								"X-Test: raw-value\r\n" +
								"Content-Type: application/x-www-form-urlencoded\r\n" +
								"\r\n" +
								"hello=world"),
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 2, 3, 4},
							NonTriggeredRules: []int{5},
						},
					},
				},
			},
		},
		{
			Title: "a base64 encoded request is decoded into the same transaction",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							// The raw request above, base64 encoded.
							EncodedRequest: "UE9TVCAvcmF3P2E9MSBIVFRQLzEuMQ0KSG9zdDogd3d3LmV4YW1wbGUuY29tDQpYLVRlc3Q6IHJhdy12YWx1ZQ0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQNCg0KaGVsbG89d29ybGQ=",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 2, 3, 4},
							NonTriggeredRules: []int{5},
						},
					},
				},
			},
		},
		{
			Title: "stop_magic leaves content-length unset",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method:    "POST",
							URI:       "/raw?a=1",
							StopMagic: true,
							Headers: map[string]string{
								"content-type": "application/x-www-form-urlencoded",
							},
							Data: "hello=world",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2, 5},
						},
					},
				},
			},
		},
	},
})
