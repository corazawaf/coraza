// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

// This profile is the reference for the assertions that used to force tests to
// be hand written against a raw transaction: exact match counts, exact log
// occurrence counts, transaction variable values and audit log shape.
//
// Each test carries its own Rules so that one profile can own a whole
// behaviour instead of one ruleset.
var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "coraza",
		Description: "Logging, variable and audit log assertions",
		Enabled:     true,
		Name:        "logging_and_variables.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "a rule matching many args logs once and repeats no tag",
			Rules: `
SecRuleEngine On
SecRule ARGS ".*" "id:1,phase:1,log,pass,tag:'some1',tag:'some2'"
`,
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?test1=123&test2=456",
						},
						Output: profile.ExpectedOutput{
							TriggeredRulesCount: map[int]int{1: 1},
							LogContainsCount: map[string]int{
								`[tag "some1"]`: 1,
								`[tag "some2"]`: 1,
							},
						},
					},
				},
			},
		},
		{
			Title: "logdata is expanded once per match",
			Rules: `
SecRuleEngine On
SecRule ARGS_GET "@rx .*" "id:1,phase:1,log,pass,logdata:'%{MATCHED_VAR} in %{MATCHED_VAR_NAME}'"
`,
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?test=1&test2=2",
						},
						Output: profile.ExpectedOutput{
							TriggeredRulesCount: map[int]int{1: 1},
							LogContainsCount: map[string]int{
								"1 in ARGS_GET:test":  1,
								"2 in ARGS_GET:test2": 1,
							},
						},
					},
				},
			},
		},
		{
			Title: "setvar results are readable as variables",
			Rules: `
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.score=5'"
SecRule TX:score "@eq 5" "id:2,phase:1,pass,log,setvar:'tx.checked=yes'"
SecAction "id:3,phase:1,pass,nolog,setvar:'tx.score=+2'"
`,
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/",
						},
						Output: profile.ExpectedOutput{
							Variables: map[string]string{
								"TX:score":   "7",
								"TX:checked": "yes",
								"TX:missing": "",
							},
							TriggeredRules: []int{2},
						},
					},
				},
			},
		},
		{
			Title: "audit log without part K carries messages with no detail",
			Rules: `
SecRuleEngine On
SecAuditEngine On
SecAuditLogParts ABCFHZ
SecRule ARGS "@rx attack" "id:1,phase:1,pass,log,msg:'attack detected'"
`,
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?payload=attack",
						},
						Output: profile.ExpectedOutput{
							AuditLog: &profile.ExpectedAuditLog{
								Parts:             "ABCFHZ",
								MessageCount:      intPtr(1),
								NoMessagesContain: []string{"should not appear"},
							},
						},
					},
				},
			},
		},
		{
			Title: "audit log carries one message per matched rule",
			Rules: `
SecRuleEngine On
SecAuditEngine On
SecAuditLogParts ABCFHKZ
SecRule ARGS "@rx attack" "id:1,phase:1,pass,log,msg:'attack detected'"
SecAction "id:2,phase:1,pass,nolog"
`,
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?payload=attack",
						},
						Output: profile.ExpectedOutput{
							AuditLog: &profile.ExpectedAuditLog{
								Parts:             "ABCFHKZ",
								MessageCount:      intPtr(1),
								MessagesContain:   []string{"attack detected"},
								NoMessagesContain: []string{"should not appear"},
							},
						},
					},
				},
			},
		},
	},
})

func intPtr(i int) *int { return &i }
