// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.rule.multiphase_evaluation

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Test if the chain action works with multiphase evaluation specific tests",
		Enabled:     true,
		Name:        "chains_multiphase.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "chains",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:     "/chain_phase2",
							Method:  "POST",
							Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
							Data:    "chain_phase2",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{10, 11, 12, 13},
						},
					},
				},
			},
		},
	},
	Rules: `
SecDebugLogLevel 9
SecRequestBodyAccess On

SecRule REQUEST_URI "/chain_phase2" "id:10, phase:2, t:none, log, setvar:'tx.set1=1', chain"
	SecRule REQUEST_BODY "chain_phase2" "setvar:'tx.set2=2', chain"
		SecRule REQUEST_BODY "chain_phase2" "setvar:'tx.set3=3'"

# ChainMinPhase between REQUEST_URI and TX has to be the user defined phase (being TX PhaseUnknown)	
SecRule REQUEST_URI "/chain_phase2" "id:11, phase:3, t:none, pass, log, chain"
	SecRule TX:set1 "@eq 1" "t:none"
SecRule REQUEST_URI "/chain_phase2" "id:12, phase:3, t:none, pass, log, chain"
	SecRule TX:set2 "@eq 2" "t:none"
SecRule REQUEST_URI "/chain_phase2" "id:13, phase:3, t:none, pass, log, chain"
	SecRule TX:set3 "@eq 3" "t:none"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Test if the chain action works with multiphase evaluation specific tests",
		Enabled:     true,
		Name:        "chains_multiphase_2.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "chains",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/chain_multi",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{2, 10, 11},
							NonTriggeredRules: []int{20},
							Interruption: &profile.ExpectedInterruption{
								Status: 403,
								Data:   "",
								RuleID: 11,
								Action: "deny",
							},
						},
					},
				},
			},
		},
	},
	// the chain should not match at phase 1 (REQUEST_URI not equal to 10), but should match at phase 2
	// rule 20 should never be reached
	// Counter variable proves that one variable of the chain is evaluated twice (at phase 1, because of the chainMinPhase,
	// and at phase 2, because it required to match to further evaluate phase:2 variables of inner rules)
	Rules: `
SecDebugLogLevel 9

SecAction "id:2, phase:2, t:none, pass, setvar:'tx.set1=10'"
SecRule REQUEST_URI "/chain_multi" "id:10, phase:2, t:none, setvar:'tx.counter=+1', log, pass, chain"
	SecRule REQUEST_URI|TX:set1 "@eq 10" "t:none"
SecRule TX:counter "@eq 2" "id:11, phase:2, t:none, deny, status:403, log"
SecAction "id:20, phase:2, t:none, deny, status:503"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Test if CRS like chain action works with multiphase evaluation",
		Enabled:     true,
		Name:        "chains_multiphase_crs.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "chains",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/",
							Headers: map[string]string{
								"payload": "java.Runtime"},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{944110},
							NonTriggeredRules: []int{11, 12},
							Interruption: &profile.ExpectedInterruption{
								Status: 403,
								Data:   "",
								RuleID: 944110,
								Action: "deny",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/",
							Headers: map[string]string{
								"Content-Type": "application/x-www-form-urlencoded"},
							Data: "test=java.Runtime",
						},
						Output: profile.ExpectedOutput{
							// We expect that the chain is evaluated on both phase 1 and 2, but only at phase 2 it matches
							TriggeredRules:    []int{944110, 11},
							NonTriggeredRules: []int{12},
							Interruption: &profile.ExpectedInterruption{
								Status: 403,
								Data:   "",
								RuleID: 944110,
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

SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_HEADERS|XML:/*|XML://@* "@rx (?:runtime|processbuilder)" \
    "id:944110,\
    phase:2,\
    deny,\
	status:403,\
    t:none,t:lowercase,\
    chain"
    SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_HEADERS|XML:/*|XML://@* "@rx (?:unmarshaller|base64data|java\.)" \
        "setvar:'tx.score=+1'"
SecAction "id:11, phase:1, t:none, pass, log"
SecAction "id:12, phase:2, t:none, pass, log"
`,
})
