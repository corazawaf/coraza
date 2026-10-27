// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jenshu",
		Description: "a request body over SecArgumentsLimit is a request body error, rejected by rule 200002",
		Enabled:     true,
		Name:        "arguments_limit_reqbody_error.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "urlencoded body over the limit is rejected by rule 200002 with the reason in logdata",
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
							TriggeredRules:    []int{200002},
							NonTriggeredRules: []int{2},
							LogContains:       `[data "URLENCODED: SecArgumentsLimit exceeded"]`,
							Interruption: &profile.ExpectedInterruption{
								RuleID: 200002,
								Action: "deny",
								Status: 400,
							},
						},
					},
				},
			},
		},
		{
			Title: "JSON body over the limit is rejected by rule 200002",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/json",
							},
							Data: `{"a":1,"b":2,"c":3}`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{200002},
							NonTriggeredRules: []int{2},
							LogContains:       `[data "JSON: SecArgumentsLimit exceeded"]`,
							Interruption: &profile.ExpectedInterruption{
								RuleID: 200002,
								Action: "deny",
								Status: 400,
							},
						},
					},
				},
			},
		},
		{
			Title: "JSON body over the limit that also fails to parse reports both reasons",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/json",
							},
							Data: `{"a":1,"b":2,"c":3} trailing`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{2, 200002},
							LogContains:    `[data "JSON: SecArgumentsLimit exceeded; JSON: invalid JSON"]`,
							Interruption: &profile.ExpectedInterruption{
								RuleID: 200002,
								Action: "deny",
								Status: 400,
							},
						},
					},
				},
			},
		},
		{
			Title: "body at the limit is not a request body error",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/x-www-form-urlencoded",
							},
							Data: "a=1&b=2",
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{200002},
						},
					},
				},
			},
		},
		{
			Title: "query string over the limit sets the flag but is not a request body error",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=1&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1},
							NonTriggeredRules: []int{200002},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRuleEngine On
SecRequestBodyAccess On
SecArgumentsLimit 2
SecRule REQUEST_HEADERS:Content-Type "application/json" "id:100, phase:1, pass, nolog, ctl:requestBodyProcessor=JSON"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:1, phase:1, pass, log"
SecRule REQBODY_PROCESSOR_ERROR "@eq 1" "id:2, phase:2, pass, log"
SecRule REQBODY_ERROR "!@eq 0" "id:200002, phase:2, log, deny, status:400, msg:'Failed to parse request body.', logdata:'%{reqbody_error_msg}'"
`,
})
