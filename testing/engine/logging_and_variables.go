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
			// Migrated from seclang.TestRuleLogging: a nolog rule still matches
			// but must not contribute a log line.
			Title: "nolog rules match without logging",
			Rules: `
SecRule ARGS ".*" "phase:1,id:1,capture,log,pass,setvar:'tx.arg_%{tx.0}=%{tx.0}'"
SecAction "id:2,phase:1,pass,log,setvar:'tx.test=ok'"
SecAction "id:3,phase:1,pass,nolog"
`,
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?test1=123&test2=456",
						},
						Output: profile.ExpectedOutput{
							TriggeredRulesCount: map[int]int{1: 1, 2: 1, 3: 1},
							LogContainsCount: map[string]int{
								`[id "1"]`: 1,
								`[id "2"]`: 1,
								`[id "3"]`: 0,
							},
							Variables: map[string]string{"TX:test": "ok"},
						},
					},
				},
			},
		},
		{
			// Migrated from seclang.TestPrintedExtraMsgAndDataFromChainedRules.
			Title: "a chain logs every link's msg and logdata exactly once",
			Rules: `
SecRule ARGS_GET "@rx .*" "id:1,phase:1,log,chain,deny,status:403,msg:'Parent msg',logdata:'%{MATCHED_VAR} in %{MATCHED_VAR_NAME}'"
	SecRule ARGS_GET "@rx .*" "msg:'Inner message 1',logdata:'%{MATCHED_VAR} in %{MATCHED_VAR_NAME}',chain"
		SecRule ARGS_GET "@rx .*" "msg:'Inner message 2',logdata:'%{MATCHED_VAR} in %{MATCHED_VAR_NAME}'"
`,
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?test=1",
						},
						Output: profile.ExpectedOutput{
							Interruption: &profile.ExpectedInterruption{
								RuleID: 1,
								Action: "deny",
								Status: 403,
							},
							TriggeredRulesCount: map[int]int{1: 1},
							LogContainsCount: map[string]int{
								"1 in ARGS_GET:test": 3,
								"Inner message 1":    1,
								"Inner message 2":    1,
							},
						},
					},
				},
			},
		},
		{
			// Migrated from seclang.TestPrintedMultipleMsgAndDataWithMultiMatch:
			// multiMatch logs the value before and after the transformation.
			Title: "multiMatch logs logdata once per evaluated value",
			Rules: `
SecRule ARGS_GET "@rx .*" "id:9696,phase:1,log,deny,t:lowercase,status:403,msg:'msg',logdata:'%{MATCHED_VAR} in %{MATCHED_VAR_NAME}',multiMatch"
`,
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?testArgGet=tEsT1",
						},
						Output: profile.ExpectedOutput{
							Interruption: &profile.ExpectedInterruption{
								RuleID: 9696,
								Action: "deny",
								Status: 403,
							},
							LogContainsCount: map[string]int{
								"tEsT1 in ARGS_GET": 1,
								"test1 in ARGS_GET": 1,
							},
						},
					},
				},
			},
		},
		{
			// Regression for https://github.com/corazawaf/coraza/issues/1612,
			// migrated from seclang.TestMultiMatchNoDuplicateOnUnchangedTransformation.
			// A transformation reporting changed=true while producing a
			// byte-identical value made multiMatch evaluate the operator twice
			// against the same value, doubling the CRS anomaly score. The rule
			// mirrors CRS 930110; the request matches REQUEST_URI_RAW and
			// ARGS:file once each, so exactly two matches are expected (four
			// before the fix).
			Title: "multiMatch does not double count an unchanged transformation",
			Rules: `
SecRule REQUEST_URI_RAW|ARGS "@rx (?:^|[/;\x5c])\.{2,3}[/;\x5c]" "id:930110,phase:2,block,capture,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,t:cmdLine,msg:'Path Traversal',multiMatch"
`,
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?file=../../etc/passwd",
						},
						Output: profile.ExpectedOutput{
							MatchedDataCount: map[int]int{930110: 2},
						},
					},
				},
			},
		},
		{
			// Migrated from seclang.TestLogsAreNotPrintedManyTimes: a rule over
			// several variables, some of them multi-valued, still logs once.
			Title: "a rule over many variables logs once",
			Rules: `
SecRule ARGS|REQUEST_HEADERS|!ARGS:test1 ".*" "phase:1,id:1,pass,log,tag:'some1',tag:'some2'"
`,
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:     "/?test1=123&test2=456&test2=789",
							Headers: map[string]string{"test": "123"},
						},
						Output: profile.ExpectedOutput{
							TriggeredRulesCount: map[int]int{1: 1},
							LogContainsCount:    map[string]int{`[id "1"]`: 1},
						},
					},
				},
			},
		},
		{
			// Migrated from seclang.TestStatusFromInterruptions.
			Title: "status from a deny action reaches the interruption",
			Rules: `
SecRule ARGS "123" "phase:1,id:1,log,deny,status:500"
`,
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?test1=123&test2=456",
						},
						Output: profile.ExpectedOutput{
							Interruption: &profile.ExpectedInterruption{
								RuleID: 1,
								Action: "deny",
								Status: 500,
							},
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
