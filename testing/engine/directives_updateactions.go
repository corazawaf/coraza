// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "fzipi",
		Description: "Test SecRuleUpdateActionById directives",
		Enabled:     true,
		Name:        "SecRuleUpdateActionById.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "SecRuleUpdateActionById to pass",
			Stages: []profile.Stage{
				// Phase 1
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/phase1?param1=value1",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								1004,
							},
						},
					},
				},
				// Phase 2
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/phase2?param2=value2",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								1014,
							},
							Interruption: &profile.ExpectedInterruption{
								Status: 302,
								Data:   "https://www.example.com/",
								RuleID: 1014,
								Action: "redirect",
							},
						},
					},
				},
			},
		},
	},
	Rules: `
	SecRule ARGS "@contains value1" "phase:1,id:1004,deny"
    SecRule ARGS "@contains value1" "phase:1,id:1005,log"
    SecRuleUpdateActionById 1004 "pass"

    SecRule ARGS "@contains value2" "phase:2,id:1014,block,deny"
	SecRuleUpdateActionById 1014 "redirect:'https://www.example.com/',status:302"
	`,
})
