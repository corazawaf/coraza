// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.rule.multiphase_evaluation

package engine

import (
	"github.com/corazawaf/coraza/v4/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Tests skip actions",
		Enabled:     true,
		Name:        "skip.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "skip actions",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/firstskip",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 2},
							NonTriggeredRules: []int{3},
							Interruption: &profile.ExpectedInterruption{
								Status: 500,
								Data:   "",
								RuleID: 2,
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

# Skip action of rule 1 will skip the next rule (if any) of the same phase. Therefore rule 3 will be skipped and rule 2 will be triggered.
SecRule REQUEST_URI "/firstskip" "id:1, phase:1, skip:1,log"
SecRule REQUEST_URI "/firstskip" "id:2, phase:2, t:none, log, deny, status:500"
SecRule REQUEST_URI "/firstskip" "id:3, phase:1, t:none, log, deny, status:500"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Tests skip actions",
		Enabled:     true,
		Name:        "skip_2.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "skip actions",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:     "/phase_skip",
							Method:  "POST",
							Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
							Data:    "phase_skip",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{20, 21},
							Interruption: &profile.ExpectedInterruption{
								Status: 500,
								Data:   "",
								RuleID: 21,
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
SecRequestBodyAccess On

# Skip action works only within the current phase, rule 20 should not skip rule 21 
SecRule REQUEST_URI "/phase_skip" "id:20, phase:1, skip:1,log"
SecRule REQUEST_BODY "phase_skip" "id:21, phase:2, t:none, log, deny, status:500"
`,
})
var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Tests skip actions",
		Enabled:     true,
		Name:        "skip_3.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "skip actions",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:     "/phase_multi_skip",
							Method:  "POST",
							Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
							Data:    "phase_multi_skip",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{30, 31},
							NonTriggeredRules: []int{32},
						},
					},
				},
			},
		},
	},
	Rules: `
SecDebugLogLevel 5
SecRequestBodyAccess On

# Skip action works only within the current phase, rule 30 should skip rule 32, not rule 31
SecRule REQUEST_URI "/phase_multi_skip" "id:30, phase:2, skip:1,log"
SecRule REQUEST_URI "/phase_multi_skip" "id:31, phase:1,pass, log"
SecRule REQUEST_BODY "phase_multi_skip" "id:32, phase:2, t:none, log, deny, status:500"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Tests skipafter action",
		Enabled:     true,
		Name:        "skipafter.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "skipafter action",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:     "/single_skipafter_phase",
							Method:  "POST",
							Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
							Data:    "single_skipafter_phase",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{40, 41},
							Interruption: &profile.ExpectedInterruption{
								Status: 500,
								Data:   "",
								RuleID: 41,
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

# SkipAfter action works only within the current phase
SecRule REQUEST_URI "/single_skipafter_phase" "id:40, phase:1, skipAfter:LOCATION_ONE,log"
SecRule REQUEST_URI|REQUEST_BODY "single_skipafter_phase" "id:41, phase:2, t:none, log, deny, status:500"
SecMarker LOCATION_ONE
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Tests skipafter action",
		Enabled:     true,
		Name:        "skipafter_2.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "skipafter action",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:     "/multi_skipafter_phase",
							Method:  "POST",
							Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
							Data:    "multi_skipafter_phase",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{50, 51},
							NonTriggeredRules: []int{52},
						},
					},
				},
			},
		},
	},
	Rules: `
SecDebugLogLevel 5

# skipAfter action works only within the current phase, rule 50 should skip rule 52, not rule 51
SecRule REQUEST_URI "/multi_skipafter_phase" "id:50, phase:2, skipAfter:LOCATION_TWO,log"
SecRule REQUEST_URI "/multi_skipafter_phase" "id:51, phase:1,pass, log"
SecRule REQUEST_BODY "multi_skipafter_phase" "id:52, phase:2, t:none, log, deny, status:500"
SecMarker LOCATION_TWO
`,
})
