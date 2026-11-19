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
		{
			Title: "SecRuleUpdateActionById range update - deny to pass should not block",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test?id=0",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								4001, 4002,
							},
							// No interruption expected - range update changed deny to pass
						},
					},
				},
			},
		},
		{
			Title: "SecRuleUpdateActionById with several ids updates every listed rule",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test?multi=1",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								5001, 5002,
							},
							// No interruption expected - both listed rules were changed from deny to pass
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test?unlisted=1",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								5003,
							},
							// A rule that is not listed keeps its deny
							Interruption: &profile.ExpectedInterruption{
								Status: 403,
								RuleID: 5003,
								Action: "deny",
							},
						},
					},
				},
			},
		},
		{
			Title: "SecRuleUpdateActionById with a one-id range followed by another id updates both rules",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test?multirange=1",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								6001, 6002,
							},
							// No interruption expected - both rules were changed from deny to pass
						},
					},
				},
			},
		},
		{
			Title: "SecRuleUpdateActionById with a one-id range applies the update once",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test?once=1",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								7001, 7003,
							},
							NonTriggeredRules: []int{
								7002,
							},
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

	# Test 4: Range update - same scenario as test 3 but with two rules updated via range
	SecRule ARGS:id "@eq 0" "id:4001, phase:1,deny,status:403,msg:'Invalid id',log,auditlog"
	SecRule ARGS:id "@eq 0" "id:4002, phase:1,deny,status:403,msg:'Invalid id',log,auditlog"
	SecRuleUpdateActionById 4001-4002 "log,pass"

	# Test 5: Several ids in one directive - every listed rule is updated, a rule left out keeps its deny
	SecRule ARGS:multi "@eq 1" "id:5001, phase:1,deny,status:403,log"
	SecRule ARGS:multi "@eq 1" "id:5002, phase:1,deny,status:403,log"
	SecRule ARGS:unlisted "@eq 1" "id:5003, phase:1,deny,status:403,log"
	SecRuleUpdateActionById 5001 5002 "log,pass"

	# Test 6: A one-id range followed by another id - both rules are updated
	SecRule ARGS:multirange "@eq 1" "id:6001, phase:1,deny,status:403,log"
	SecRule ARGS:multirange "@eq 1" "id:6002, phase:1,deny,status:403,log"
	SecRuleUpdateActionById 6001-6001 6002 "log,pass"

	# Test 7: A one-id range applies the update once - the added setvar runs once, so tx.once is 1, not 2
	SecRule ARGS:once "@eq 1" "id:7001, phase:1,pass,log"
	SecRuleUpdateActionById 7001-7001 "setvar:tx.once=+1"
	SecRule TX:once "@eq 2" "id:7002, phase:1,deny,status:403,log"
	SecRule TX:once "@eq 1" "id:7003, phase:1,pass,log"
	`,
})
