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
							// No interruption expected because pass action should replace deny
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
		{
			Title: "SecRuleUpdateActionById with non-disruptive actions preserves disruptive action",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test?param=trigger",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								2001,
							},
							Interruption: &profile.ExpectedInterruption{
								Status: 403,
								RuleID: 2001,
								Action: "deny",
							},
						},
					},
				},
			},
		},
		{
			Title: "SecRuleUpdateActionById issue #1414 - deny to pass should not block",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test?id=0",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								3001,
							},
							// No interruption expected - this is the bug from issue #1414
						},
					},
				},
			},
		},
	},
	Rules: `
	# Test 1: Updating deny to pass
	SecRule ARGS "@contains value1" "phase:1,id:1004,deny"
    SecRule ARGS "@contains value1" "phase:1,id:1005,log"
    SecRuleUpdateActionById 1004 "pass"

    SecRule ARGS "@contains value2" "phase:2,id:1014,block,deny"
	SecRuleUpdateActionById 1014 "redirect:'https://www.example.com/',status:302"

	# Test 2: Updating with non-disruptive actions should preserve disruptive action
	SecRule ARGS:param "@contains trigger" "phase:1,id:2001,deny,status:403"
	SecRuleUpdateActionById 2001 "log,auditlog"

	# Test 3: Issue #1414 - exact scenario from the GitHub issue
	SecRule ARGS:id "@eq 0" "id:3001, phase:1,deny,status:403,msg:'Invalid id',log,auditlog"
	SecRuleUpdateActionById 3001 "log,pass"
	`,
})
