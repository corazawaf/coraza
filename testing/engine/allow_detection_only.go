// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.rule.multiphase_evaluation

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

// These two profiles use the same rules to show the behavioral difference between On and DetectionOnly.
// In On mode, allow is a disruptive action that skips subsequent rules.
// In DetectionOnly mode, disruptive actions (including allow) do not affect rule flow,
// so all matching rules are evaluated.
var allowRules = `
SecDebugLogLevel 5
SecDefaultAction "phase:1,log,pass"

# Full allow: rule 2 is skipped in On mode, but still evaluated in DetectionOnly
SecRule REQUEST_URI "/allow_me" "id:1,phase:1,allow,log,msg:'ALLOWED'"
SecRule REQUEST_URI "/allow_me" "id:2,phase:1,deny,log,msg:'Should be skipped by allow'"

# allow:phase skips remaining phase 1 rules in On mode, but not in DetectionOnly
SecRule REQUEST_URI "/partial_allow" "id:11,phase:1,allow:phase,log,msg:'Allowed in this phase only'"
SecRule REQUEST_URI "/partial_allow" "id:12,phase:1,deny,log,msg:'Should be skipped by allow phase'"
SecRule REQUEST_URI "/partial_allow" "id:13,phase:1,deny,log,msg:'Should be skipped by allow phase'"
SecRule REQUEST_URI "/partial_allow" "id:22,phase:2,deny,log,status:500,msg:'Denied in phase 2'"
SecRule REQUEST_URI "/partial_allow" "id:23,phase:2,deny,log,status:501,msg:'Denied in phase 2'"
`

// allow_on.yaml: baseline with SecRuleEngine On.
// Rule 1 allows, so rule 2 is skipped.
// Rule 11 allows phase 1, so rules 12 and 13 are skipped
// but rule 22 in phase 2 still triggers and interrupts.
// rule 23 in phase 2 is not triggered because of the previous interruption.
var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Test allow action with SecRuleEngine On (baseline for DetectionOnly comparison)",
		Enabled:     true,
		Name:        "allow_on.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "allow with engine on",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/allow_me?key=value",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1},
							NonTriggeredRules: []int{2},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/partial_allow?key=value",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{11, 22},
							NonTriggeredRules: []int{12, 13, 23},
							Interruption: &profile.ExpectedInterruption{
								Status: 500,
								RuleID: 22,
								Action: "deny",
							},
						},
					},
				},
			},
		},
	},
	Rules: "SecRuleEngine On\n" + allowRules,
})

// allow_detection_only.yaml: same rules as above but with SecRuleEngine DetectionOnly.
// In DetectionOnly mode, allow does not affect rule flow: all matching rules are still evaluated.
// This differs from On mode where allow skips subsequent rules.
var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Test allow action with SecRuleEngine DetectionOnly (same rules as allow_on.yaml)",
		Enabled:     true,
		Name:        "allow_detection_only.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "allow with engine detection only",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/allow_me?key=value",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/partial_allow?key=value",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{11, 12, 13, 22, 23},
						},
					},
				},
			},
		},
	},
	Rules: "SecRuleEngine DetectionOnly\n" + allowRules,
})
