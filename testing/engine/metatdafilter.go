// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "roshan.piyush",
		Description: "Test if the matchers works",
		Enabled:     true,
		Name:        "metadatafilter.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "actions",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							DestAddr: "127.0.0.1",
							Method:   "GET",
							URI:      "/test.php?m1=abc&m2=true&m3=xabc123&m4=abc.sjdjd&m5=abc@123",
							Headers: map[string]string{
								"content-type": "application/json",
							},
						},

						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								26,
								27,
								32,
							},
							NonTriggeredRules: []int{
								28,
								29,
								30,
								31,
							},
						},
					},
				},
			},
		},
	},
	Rules: `
SecDebugLogLevel 9
SecRule ARGS "@rx 123" "block,id:26, log, phase: 2, tag:'metadatafilter/ascii'"
SecRule ARGS "@rx true" "block,id:27, log, phase: 2, tag:'metadatafilter/boolean,alphanumeric'"
SecRule ARGS "@rx abc" "block,id:28, log, phase: 2, tag:'metadatafilter/boolean'"
SecRule ARGS "@rx abc" "block,id:29, log, phase: 2, tag:'metadatafilter/alphanumeric'"
SecRule ARGS "@rx @" "block,id:30, log, phase: 2, tag:'metadatafilter/boolean,alphanumeric'"
SecRule ARGS "@rx @" "block,id:31, log, phase: 2, tag:'metadatafilter/boolean'"
SecRule ARGS "@rx @" "block,id:32, log, phase: 2, tag:'metadatafilter/ascii'"
SecRule ARGS "@rx @" "block,id:33, log, phase: 2, tag:'metadatafilter/boolean,not_alphanumeric'"
`,
})
