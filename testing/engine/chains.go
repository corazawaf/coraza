// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the chain action works",
		Enabled:     true,
		Name:        "chains.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "chains",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test1.php?id=12345",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 1313},
							NonTriggeredRules: []int{2, 200, 20},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test2.php?Var2=prepayloadpost",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 200},
							NonTriggeredRules: []int{2, 1313, 20},
							LogContains:       "found within ARGS_GET:Var2: prepayloadpost",
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/testcase3.php?Var3=pre3payloadpost",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 300},
							NonTriggeredRules: []int{2, 1313, 20},
							LogContains:       "found within ARGS_GET:Var3: pre3payloadpost",
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/testcase4.php?Var4=pre4payloadpost",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 400},
							NonTriggeredRules: []int{2, 1313, 20},
							LogContains:       "found within ARGS_GET:Var4: pre4payloadpost",
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test3.php",
							Headers: map[string]string{
								"Host": "attack20ing.com",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 20},
							NonTriggeredRules: []int{2, 1313, 21},
							LogContains:       "FoundChain20 attack20ing.com in REQUEST_HEADERS:Host",
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test4.php",
							Headers: map[string]string{
								"Host": "attack21ing.com",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 21},
							NonTriggeredRules: []int{20, 2, 1313},
							LogContains:       "FoundSubChain21 REQUEST_HEADERS:Host in MATCHED_VARS_NAMES",
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id: 1, log, chain"
  SecAction "msg:'chain 2',chain"
  SecAction "msg:'chain 3',chain"
  SecAction "msg:'chain 4'"
      
SecAction "id: 2, log, chain"
  SecAction "chain"
  SecAction "chain"
  SecRule ARGS "@noMatch" ""

SecRule REQUEST_URI "@rx (\d\d+)" "id:1313, chain, log"
  SecRule REQUEST_METHOD "GET" ""

SecRule ARGS_GET "@rx prepayloadpost"  "id:200, phase:2, log, msg:'Rule Parent 200', \
  logdata:'Matched Data: %{TX.0} found within %{TX.200_MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
  setvar:'tx.200_matched_var_name=%{MATCHED_VAR_NAME}',\
  chain"
  SecRule MATCHED_VAR "@rx pre" "chain"
    SecRule MATCHED_VAR "@rx post"

SecRule ARGS_GET:Var3 "@rx pre3payloadpost"  "id:300, phase:2, log, msg:'Rule Parent 300', \
  logdata:'Matched Data: %{TX.0} found within %{TX.300_MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
  setvar:'tx.300_matched_var_name=%{MATCHED_VAR_NAME}',\
  chain"
  SecRule MATCHED_VAR "@rx pre" "chain"
    SecRule MATCHED_VAR "@rx post"

SecRule ARGS_GET:Var4 "@rx pre4payloadpost"  "id:400, phase:2, log, msg:'Rule Parent 400', \
  logdata:'Matched Data: %{TX.0} found within %{TX.400_MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
  setvar:'tx.400_matched_var_name=%{MATCHED_VAR_NAME}',\
  chain"
  SecRule MATCHED_VAR "@rx pre" "chain"
    SecRule MATCHED_VAR "@rx post"

SecRule REQUEST_HEADERS "@rx attack20" \
  "id:20,\
  phase:1,\
  log,\
  msg:'Chained rule Parent test',\
  logdata:'FoundChain20 %{MATCHED_VAR} in %{MATCHED_VAR_NAME}',\
  chain"
  SecRule MATCHED_VARS_NAMES "@rx Host" \
    "chain"
    SecRule REQUEST_HEADERS:Host "@rx attack20" \
      ""

SecRule REQUEST_HEADERS "@rx attack21" \
  "id:21,\
  phase:1,\
  log,\
  chain"
  SecRule MATCHED_VARS_NAMES "@rx (?i:host)" \
    "msg:'Sub Chain Rule',\
    logdata:'FoundSubChain21 %{MATCHED_VAR} in %{MATCHED_VAR_NAME}',\
    chain"
    SecRule MATCHED_VAR_NAME "@rx MATCHED_VARS_NAMES" \
    "msg:'Sub Sub Chain Rule',\
    logdata:'FoundSubSubChain21 %{MATCHED_VAR} in %{MATCHED_VAR_NAME}'"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Tests the number of expected matches against a chained rule",
		Enabled:     true,
		Name:        "chains_counter.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "chains_number_matches",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/test",
							Method: "POST",
							Headers: map[string]string{
								"Content-type":   "application/x-www-form-urlencoded",
								"custom_header1": "test",
							},
							Data: "test",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
	},
	Rules: `
SecDebugLogLevel 9
SecRequestBodyAccess On

SecRule REQUEST_URI "test" "id:1, phase:2, t:none, pass, log, chain"
	SecRule REQUEST_URI|REQUEST_BODY|REQUEST_HEADERS:custom_header1 "test" "setvar:'tx.counter=+1'"
	SecRule TX:counter "@eq 3" "id:2, phase:2, t:none, pass, log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Tests the number of expected matches against a chained rule",
		Enabled:     true,
		Name:        "chains_counter_2.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "chains_number_matches",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/test",
							Method: "POST",
							Headers: map[string]string{
								"Content-type":   "application/x-www-form-urlencoded",
								"custom_header1": "test",
							},
							Data: "test",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
	},
	Rules: `
SecDebugLogLevel 9
SecRequestBodyAccess On

SecRule REQUEST_URI|REQUEST_HEADERS "test" "id:1, phase:2, t:none, pass, log, chain"
    SecRule REQUEST_URI|REQUEST_HEADERS "test" "chain"
        SecRule REQUEST_BODY|REQUEST_HEADERS:custom_header1|REQUEST_HEADERS "test" "setvar:'tx.counter=+1'"
SecRule TX:counter "@eq 3" "id:2, phase:2, t:none, pass, log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "adilalperenciftci",
		Description: "evalDepth runs the rest of the chain once per match with that match's MATCHED_VAR and captures",
		Enabled:     true,
		Name:        "chains_eval_depth.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "chains_eval_depth",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=attack1&b=attack2",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{101},
							NonTriggeredRules: []int{102, 103, 104},
							LogContains:       `[data "depth attack1"]`,
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=attack2&b=attack3",
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{101, 102, 103, 104},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=admin-50&b=guest-5",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{102},
							NonTriggeredRules: []int{103, 104},
							LogContains:       `[data "user admin over 50"]`,
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=admin-5&b=guest-50",
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{102, 103, 104},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?q=k1&r=k9",
							Headers: map[string]string{
								"X-A": "k2",
								"X-B": "k9",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{103},
							NonTriggeredRules: []int{104},
							LogContains:       `[data "pair k9"]`,
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?q=k1&r=k8",
							Headers: map[string]string{
								"X-A": "k2",
								"X-B": "k9",
							},
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{103, 104},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=A&b=B",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{105, 106},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule ARGS "@rx ^(attack\d+)$" "id:101,phase:1,log,capture,chain,evalDepth,logdata:'depth %{TX.1}'"
  SecRule TX:1 "@streq attack1" ""

SecRule ARGS "@rx ^(\w+)-(\d+)$" "id:102,phase:1,log,capture,chain,evalDepth,logdata:'user %{TX.1} over %{TX.2}'"
  SecRule TX:2 "@gt 10" "chain"
    SecRule TX:1 "@streq admin" ""

SecRule ARGS_GET "@rx ^(k\d)$" "id:103,phase:1,log,capture,chain,evalDepth,logdata:'pair %{TX.1}'"
  SecRule REQUEST_HEADERS:/^x-/ "@rx ^k" "chain"
    SecRule MATCHED_VAR "@streq %{tx.1}" ""

SecRule ARGS "@rx ^(attack\d+)$" "id:104,phase:1,log,capture,chain,evalDepth"
  SecRule TX:1 "@streq nothing" ""

# Non-disruptive actions on chain links run for every attempted parent context,
# including failed paths. The A attempt adds 5 before it fails, then B adds 5.
SecRule ARGS_GET:a|ARGS_GET:b "@rx ^(A|B)$" "id:105,phase:1,log,capture,chain,evalDepth"
  SecRule REQUEST_METHOD "@streq GET" "setvar:'tx.eval_depth_score=+5',chain"
    SecRule TX:1 "@streq B" ""
SecRule TX:eval_depth_score "@eq 10" "id:106,phase:1,pass,log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "fzipi",
		Description: "SecIgnoreRuleCompilationErrors drops a chain whole when one of its links fails to compile",
		Enabled:     true,
		Name:        "chains_ignore_compilation_errors.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "chains with a faulty link are dropped whole",
			Stages: []profile.Stage{
				{
					// The links of chains 100, 130 and 160 must not load on their own, so
					// the ctl does not run, and neither the faulty chain 120 nor the
					// marker after chain 140 drops rule 200, which still blocks.
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/partner/orders?q=attack",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{200},
							NonTriggeredRules: []int{100, 110, 120, 130, 140, 150, 160},
							Interruption: &profile.ExpectedInterruption{
								RuleID: 200,
								Action: "deny",
								Status: 403,
							},
						},
					},
				},
				{
					// The link after the faulty middle link of chain 110 must neither
					// complete that chain nor load on its own.
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/pay?card=1",
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{100, 110, 120, 130, 140, 150, 160, 200},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRuleEngine On
SecIgnoreRuleCompilationErrors On

SecRule UNKNOWN_VARIABLE "@unconditionalMatch" "id:100,phase:1,pass,nolog,chain"
    SecRule REQUEST_URI "@beginsWith /partner/" "ctl:ruleEngine=Off"

SecRule REQUEST_URI "@beginsWith /pay" "id:110,phase:2,deny,status:403,chain"
    SecRule ARGS:card "@unknownOperator x" "chain"
        SecRule ARGS:card "@rx ." "setvar:tx.chain_110_leak=1"
SecRule TX:chain_110_leak "@eq 1" "id:150,phase:2,pass,log"

SecRule REQUEST_URI "@beginsWith /pay" "id:120,phase:2,deny,status:403,chain"
    SecRule ARGS:card "@unknownOperator x"

# Malformed: the operator is not quoted.
SecRule REQUEST_URI @beginsWith /partner/ "id:130,phase:1,pass,nolog,chain"
    SecRule REQUEST_URI "@beginsWith /partner/" "ctl:ruleEngine=Off"

# Malformed: the actions are not quoted.
SecRule REQUEST_URI "@beginsWith /partner/" id:160,phase:1,pass,nolog,chain
    SecRule REQUEST_URI "@beginsWith /partner/" "ctl:ruleEngine=Off"

# A marker ends a chain, even one left open by a faulty starter.
SecRule UNKNOWN_VARIABLE "@unconditionalMatch" "id:140,phase:1,pass,nolog,chain"
SecMarker END_140

SecRule ARGS "@contains attack" "id:200,phase:2,deny,status:403"
`,
})
