// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "sts",
		Description: "Test if disruptive actions trigger an interruption",
		Enabled:     true,
		Name:        "disruptive_actions.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "disruptive_actions",
			Stages: []profile.Stage{
				// Phase 1
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/redirect1",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1},
							Interruption: &profile.ExpectedInterruption{
								Status: 302,
								Data:   "https://www.example.com",
								RuleID: 1,
								Action: "redirect",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/deny1",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{2},
							Interruption: &profile.ExpectedInterruption{
								Status: 403,
								Data:   "",
								RuleID: 2,
								Action: "deny",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/drop1",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{3},
							Interruption: &profile.ExpectedInterruption{
								Status: 0,
								Data:   "",
								RuleID: 3,
								Action: "drop",
							},
						},
					},
				},
				// Phase 2
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/redirect2",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{21},
							Interruption: &profile.ExpectedInterruption{
								Status: 302,
								Data:   "https://www.example.com",
								RuleID: 21,
								Action: "redirect",
							},
						},
					},
				},
				// Phase 2
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/redirect2",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{21},
							Interruption: &profile.ExpectedInterruption{
								Status: 302,
								Data:   "https://www.example.com",
								RuleID: 21,
								Action: "redirect",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/redirect6",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{61},
							Interruption: &profile.ExpectedInterruption{
								Status: 302,
								Data:   "https://www.example.com",
								RuleID: 61,
								Action: "redirect",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/redirect7",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{62},
							Interruption: &profile.ExpectedInterruption{
								Status: 307,
								Data:   "https://www.example.com",
								RuleID: 62,
								Action: "redirect",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/redirect8",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{63},
							Interruption: &profile.ExpectedInterruption{
								Status: 302,
								Data:   "https://www.example.com",
								RuleID: 63,
								Action: "redirect",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/deny2",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{22},
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
							URI: "/drop2",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{23},
							Interruption: &profile.ExpectedInterruption{
								Status: 0,
								Data:   "",
								RuleID: 23,
								Action: "drop",
							},
						},
					},
				},
				// Phase 3
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/redirect3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{31},
							Interruption: &profile.ExpectedInterruption{
								Status: 302,
								Data:   "https://www.example.com",
								RuleID: 31,
								Action: "redirect",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/deny3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{32},
							Interruption: &profile.ExpectedInterruption{
								Status: 500,
								Data:   "",
								RuleID: 32,
								Action: "deny",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/drop3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{33},
							Interruption: &profile.ExpectedInterruption{
								Status: 0,
								Data:   "",
								RuleID: 33,
								Action: "drop",
							},
						},
					},
				},
				// Phase 4
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/redirect4",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{41},
							Interruption: &profile.ExpectedInterruption{
								Status: 302,
								Data:   "https://www.example.com",
								RuleID: 41,
								Action: "redirect",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/deny4",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{42},
							Interruption: &profile.ExpectedInterruption{
								Status: 500,
								Data:   "",
								RuleID: 42,
								Action: "deny",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/drop4",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{43},
							Interruption: &profile.ExpectedInterruption{
								Status: 0,
								Data:   "",
								RuleID: 43,
								Action: "drop",
							},
						},
					},
				},
				// Phase 5
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/redirect5",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{51},
							Interruption: &profile.ExpectedInterruption{
								Status: 302,
								Data:   "https://www.example.com",
								RuleID: 51,
								Action: "redirect",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/deny5",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{52},
							Interruption: &profile.ExpectedInterruption{
								Status: 500,
								Data:   "",
								RuleID: 52,
								Action: "deny",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/drop5",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{53},
							Interruption: &profile.ExpectedInterruption{
								Status: 0,
								Data:   "",
								RuleID: 53,
								Action: "drop",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/default/block",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{103},
							LogContains:    "WOOOP_BLOCKED_BY_CORAZA_TEST",
							Interruption: &profile.ExpectedInterruption{
								Status: 501,
								Data:   "",
								RuleID: 103,
								Action: "deny",
							},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule REQUEST_URI "/redirect1$" "phase:1,id:1,log,status:302,redirect:https://www.example.com"
# deny action defaults to status 403
SecRule REQUEST_URI "/deny1$" "phase:1,id:2,log,deny"
SecRule REQUEST_URI "/drop1$" "phase:1,id:3,log,drop"

SecRule REQUEST_URI "/redirect2$" "phase:2,id:21,log,status:302,redirect:https://www.example.com"
SecRule REQUEST_URI "/deny2$" "phase:2,id:22,log,status:500,deny"
SecRule REQUEST_URI "/drop2$" "phase:2,id:23,log,drop"

SecRule REQUEST_URI "/redirect3$" "phase:3,id:31,log,status:302,redirect:https://www.example.com"
SecRule REQUEST_URI "/deny3$" "phase:3,id:32,log,status:500,deny"
SecRule REQUEST_URI "/drop3$" "phase:3,id:33,log,drop"

SecRule REQUEST_URI "/redirect4$" "phase:4,id:41,log,status:302,redirect:https://www.example.com"
SecRule REQUEST_URI "/deny4$" "phase:4,id:42,log,status:500,deny"
SecRule REQUEST_URI "/drop4$" "phase:4,id:43,log,drop"

SecRule REQUEST_URI "/redirect5$" "phase:5,id:51,log,status:302,redirect:https://www.example.com"
SecRule REQUEST_URI "/deny5$" "phase:5,id:52,log,status:500,deny"
SecRule REQUEST_URI "/drop5$" "phase:5,id:53,log,drop"

SecRule REQUEST_URI "/redirect6$" "phase:2,id:61,log,redirect:https://www.example.com"
SecRule REQUEST_URI "/redirect7$" "phase:2,id:62,log,status:307,redirect:https://www.example.com"
SecRule REQUEST_URI "/redirect8$" "phase:2,id:63,log,status:401,redirect:https://www.example.com"


# Rule 103 is missing the phase, therefore phase:2 is implicitly applied with its related default actions
# So we will expect a deny with 501 response for the blocking action.
SecDefaultAction "phase:2,deny,status:501,log"
SecRule REQUEST_URI "/default/block" "id:103,block,logdata:'WOOOP_BLOCKED_BY_CORAZA_TEST'"
`,
})
