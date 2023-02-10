// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "fzipi",
		Description: "Test if the allow action works",
		Enabled:     true,
		Name:        "allow.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "actions",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/allow_me?key=value&key=other_value",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								1,
							},
							NonTriggeredRules: []int{
								2,
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/partial_allow?key=value&key=other_value",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								11,
								22,
							},
							NonTriggeredRules: []int{
								12,
							},
							Interruption: &profile.ExpectedInterruption{
								Status: 500,
								Data:   "",
								RuleID: 22,
								Action: "deny",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/request_allow?key=value&key=other_value",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								31,
								42,
							},
							NonTriggeredRules: []int{
								32,
							},
							Interruption: &profile.ExpectedInterruption{
								Status: 500,
								Data:   "",
								RuleID: 42,
								Action: "deny",
							},
						},
					},
				},
			},
		},
	},
	Rules: `
SecDebugLogLevel 5
SecRule REQUEST_URI "/allow_me" "id:1,phase:1,allow,msg:'ALLOWED'"
SecRule REQUEST_URI "/allow_me" "id:2,phase:1,deny,msg:'DENIED'"

SecRule REQUEST_URI "/partial_allow" "id:11,phase:1,allow:phase,msg:'Allowed in this phase only'"
SecRule REQUEST_URI "/partial_allow" "id:12,phase:1,deny,msg:'NOT DENIED'"
SecRule REQUEST_URI "/partial_allow" "id:22,phase:2,deny,status:500,msg:'DENIED'"

SecRule REQUEST_URI "/request_allow" "id:31,phase:1,allow:request,msg:'Allowed at the request.'"
SecRule REQUEST_URI "/request_allow" "id:32,phase:2,deny,msg:'NOT DENIED'"
SecRule REQUEST_URI "/request_allow" "id:42,phase:3,deny,status:500,msg:'DENIED'"

`,
})
