// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.rule.multiphase_evaluation

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
			Title: "allow action",
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
								13,
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
								33,
								34,
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
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/useless_request_allow",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								45,
								46,
							},
							Interruption: &profile.ExpectedInterruption{
								Status: 500,
								Data:   "",
								RuleID: 46,
								Action: "deny",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:     "/allow_only_response?key=allow_only_response",
							Method:  "POST",
							Headers: map[string]string{"Content-type": "application/x-www-form-urlencoded"},
							Data:    "allow_only_response",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								50,
								51,
							},
							NonTriggeredRules: []int{
								61,
								62,
							},
							Interruption: &profile.ExpectedInterruption{
								Status: 500,
								Data:   "",
								RuleID: 51,
								Action: "deny",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/response_allow",
							Method: "POST",
							Headers: map[string]string{
								"Content-type": "application/x-www-form-urlencoded",
							},
							Data: "response_allow",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{70},
							NonTriggeredRules: []int{71},
							Interruption: &profile.ExpectedInterruption{
								Status: 500,
								Data:   "",
								RuleID: 70,
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
SecDefaultAction "phase:1,log,pass"

SecRule REQUEST_URI "/allow_me" "id:1,phase:1,allow,log,msg:'ALLOWED'"
SecRule REQUEST_URI "/allow_me" "id:2,phase:1,deny,log,msg:'DENIED'"

# Rule 11 allows phase 1, so rule 12 and 13, being both phase 1, are not triggered. Rule 22 is then triggered in phase 2.
SecRule REQUEST_URI "/partial_allow" "id:11,phase:1,allow:phase,msg:'Allowed in this phase only'"
SecRule REQUEST_URI "/partial_allow" "id:12,phase:1,deny,msg:'NOT DENIED'"
SecRule REQUEST_URI "/partial_allow" "id:13,phase:1,deny,msg:'NOT DENIED'"
SecRule REQUEST_URI "/partial_allow" "id:22,phase:2,deny,log,status:500,msg:'DENIED'"

# Rule 31 allows all the request phases (1 and 2), therefore rules 32, 33 and 34 should not be triggered. Rule 42 is
# expected to be triggered at phase 3.
SecRule REQUEST_URI "/request_allow" "id:31,phase:1,allow:request,log,msg:'Allowed at the request'"
SecRule REQUEST_URI "/request_allow" "id:32,phase:1,deny,log,msg:'NOT DENIED'"
SecRule REQUEST_URI "/request_allow" "id:33,phase:2,deny,log,msg:'NOT DENIED'"
SecRule REQUEST_URI "/request_allow" "id:34,phase:2,deny,log,msg:'NOT DENIED'"
SecRule REQUEST_URI "/request_allow" "id:42,phase:3,deny,log,status:500,msg:'DENIED'"

# Rule 45 allows only request phases (1 and 2), it should not impact on phase 3.
# Therefore, rule 46 is expected to be triggered.
SecRule REQUEST_URI "/useless_request_allow" "id:45,phase:1,allow:request,log,msg:'Allowed at the request'"
SecRule REQUEST_URI "/useless_request_allow" "id:46,phase:3,deny,log,status:500,msg:'DENIED'"

# Rule 50 allows only the current phase (phase 1), it should not impact any other rule (being part of other phases).
# Rule 61 is meant to allow only from phase 3 (so phase 3 and 4), rule 51, at phase 2 should deny the request
# before reaching phase 3. Therefore rule 61 and 62 should not be triggered.
# Suitable for testing that allow:phase is not propagated to other phases
SecRule REQUEST_URI "/allow_only_response" "id:50,phase:1,allow:phase,log, msg:'Allowed phase 1'"
SecRule REQUEST_BODY "allow_only_response" "id:51,phase:2,deny,log,status:500,msg:'Denied request'"
SecRule REQUEST_URI "/allow_only_response" "id:61,phase:3,allow,log,msg:'Allowed Response not triggered'"
SecRule REQUEST_URI "/allow_only_response" "id:62,phase:4,deny,log,msg:'Deny response not triggered'"

# Rule 70 should deny the request at phase:2 before rule 71.
# Suitable for testing multiphase evaluation combined with allow actions.
SecRule REQUEST_BODY "response_allow" "id:70,phase:2,deny,log,status:500,msg:'Denied request'"
SecRule REQUEST_URI "/response_allow" "id:71,phase:3,allow,log,msg:'Allowed Response not triggered'"
`,
})
