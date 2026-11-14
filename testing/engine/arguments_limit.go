// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

// argumentsLimitRules caps every argument source at two values. Rule 1 runs in
// phase 1 and rule 2 in phase 2, so a test can tell which phases were evaluated.
const argumentsLimitRules = `
SecRequestBodyAccess On
SecArgumentsLimit 2
SecRule ARGS_GET "@rx ." "id:1, phase:1, pass, log"
SecRule ARGS_POST "@rx ." "id:2, phase:2, pass, log"
`

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jenshu",
		Description: "SecArgumentsLimitAction Reject (the default) rejects a request whose arguments were dropped, after the rules of that phase",
		Enabled:     true,
		Name:        "arguments_limit_reject.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "query string over the limit is rejected after phase 1 rules",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=1&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1},
							NonTriggeredRules: []int{2},
							Interruption: &profile.ExpectedInterruption{
								Action: "deny",
								Status: 400,
							},
						},
					},
				},
			},
		},
		{
			Title: "query string at the limit is not rejected",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=1&b=2",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1},
						},
					},
				},
			},
		},
		{
			Title: "urlencoded body over the limit is rejected after phase 2 rules",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/?a=1",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/x-www-form-urlencoded",
							},
							Data: "a=1&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
							Interruption: &profile.ExpectedInterruption{
								Action: "deny",
								Status: 400,
							},
						},
					},
				},
			},
		},
		{
			Title: "a phase 1 ctl:ruleEngine=DetectionOnly exempts a route",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/bulk?a=1&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 3},
							DetectionOnlyInterruption: &profile.ExpectedInterruption{
								Action: "deny",
								Status: 400,
							},
						},
					},
				},
			},
		},
		{
			Title: "a phase 1 ctl:ruleEngine=Off exempts a route",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/off?a=1&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 7},
						},
					},
				},
			},
		},
		{
			Title: "a phase 1 allow does not exempt the request",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/allowed?a=1&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 6},
							Interruption: &profile.ExpectedInterruption{
								Action: "deny",
								Status: 400,
							},
						},
					},
				},
			},
		},
		{
			Title: "response arguments over the limit do not trigger the Reject fallback",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/",
						},
						Output: profile.ExpectedOutput{
							Headers: map[string]string{
								"content-type": "application/json",
							},
							Data:           `{"a":1,"b":2,"c":3}`,
							TriggeredRules: []int{5},
						},
					},
				},
			},
		},
	},
	Rules: "SecRuleEngine On\n" + argumentsLimitRules + `
SecRule REQUEST_FILENAME "@streq /bulk" "id:3, phase:1, pass, log, ctl:ruleEngine=DetectionOnly"

SecResponseBodyAccess On
SecResponseBodyMimeType application/json
SecRule RESPONSE_HEADERS:content-type "application/json" "id:4, phase:3, pass, nolog, ctl:responseBodyProcessor=JSON"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:5, phase:4, pass, log"
SecRule REQUEST_FILENAME "@streq /allowed" "id:6, phase:1, allow, log"
SecRule REQUEST_FILENAME "@streq /off" "id:7, phase:1, pass, log, ctl:ruleEngine=Off"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jenshu",
		Description: "Rules on ARGUMENTS_LIMIT_REACHED act before SecArgumentsLimitAction Reject",
		Enabled:     true,
		Name:        "arguments_limit_rules_first.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "rule 200004 rejects query string overflow with its rule id",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=1&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							Interruption: &profile.ExpectedInterruption{
								RuleID: 200004,
								Action: "deny",
								Status: 400,
							},
						},
					},
				},
			},
		},
		{
			Title: "rule 200005 rejects body overflow with its rule id",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/x-www-form-urlencoded",
							},
							Data: "a=1&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							Interruption: &profile.ExpectedInterruption{
								RuleID: 200005,
								Action: "deny",
								Status: 400,
							},
						},
					},
				},
			},
		},
	},
	Rules: "SecRuleEngine On\n" + argumentsLimitRules + `
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:200004, phase:1, log, deny, status:400"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:200005, phase:2, log, deny, status:400"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jenshu",
		Description: "SecArgumentsLimitAction ProcessPartial keeps the arguments that fit and only sets ARGUMENTS_LIMIT_REACHED",
		Enabled:     true,
		Name:        "arguments_limit_process_partial.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "query string over the limit is truncated, not rejected",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=1&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 3},
							NonTriggeredRules: []int{4},
						},
					},
				},
			},
		},
		{
			Title: "body over the limit is truncated, and the flag is visible from phase 2",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/x-www-form-urlencoded",
							},
							Data: "a=1&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{2, 5},
							NonTriggeredRules: []int{3, 6},
						},
					},
				},
			},
		},
	},
	Rules: "SecRuleEngine On\nSecArgumentsLimitAction ProcessPartial\n" + argumentsLimitRules + `
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:3, phase:1, pass, log"
SecRule ARGS_GET:c "@rx ." "id:4, phase:1, pass, log"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:5, phase:2, pass, log"
SecRule ARGS_POST:c "@rx ." "id:6, phase:2, pass, log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jenshu",
		Description: "SecArgumentsLimitAction Reject records, but does not perform, the interruption under SecRuleEngine DetectionOnly",
		Enabled:     true,
		Name:        "arguments_limit_detection_only.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "query string over the limit records a 400",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=1&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1},
							DetectionOnlyInterruption: &profile.ExpectedInterruption{
								Action: "deny",
								Status: 400,
							},
						},
					},
				},
			},
		},
		{
			Title: "a rule's recorded interruption is kept",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=evil&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 3},
							DetectionOnlyInterruption: &profile.ExpectedInterruption{
								RuleID: 3,
								Action: "deny",
								Status: 403,
							},
						},
					},
				},
			},
		},
		{
			Title: "after a phase 1 switch to On, a recorded interruption does not suppress the rejection",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/enforce?a=evil&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 3, 4},
							Interruption: &profile.ExpectedInterruption{
								Action: "deny",
								Status: 400,
							},
						},
					},
				},
			},
		},
		{
			Title: "after a phase 2 switch to On, a body overflow is rejected despite an earlier query overflow",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/?a=1&b=2&c=3",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/x-www-form-urlencoded",
							},
							Data: "enforce=body&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2, 5},
							Interruption: &profile.ExpectedInterruption{
								Action: "deny",
								Status: 400,
							},
						},
					},
				},
			},
		},
	},
	Rules: "SecRuleEngine DetectionOnly\n" + argumentsLimitRules + `
SecRule ARGS_GET:a "@streq evil" "id:3, phase:1, log, deny, status:403"
SecRule REQUEST_FILENAME "@streq /enforce" "id:4, phase:1, pass, log, ctl:ruleEngine=On"
# ARGS_POST keeps rule 5 in phase 2 under coraza.rule.multiphase_evaluation; REQUEST_FILENAME would run it in phase 1.
SecRule ARGS_POST:enforce "@streq body" "id:5, phase:2, pass, log, ctl:ruleEngine=On"
`,
})
