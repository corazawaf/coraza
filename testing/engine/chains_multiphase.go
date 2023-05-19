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
		Description: "Test if a chain rule is not matched twice against the same variables in different phases",
		Enabled:     true,
		Name:        "chains_multiphase_counter.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "chains_no_double_match",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1},
							NonTriggeredRules: []int{2, 3},
						},
					},
				},
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
							TriggeredRules: []int{1, 2, 3},
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
SecRule TX:counter "!@eq 1" "id:2, phase:2, t:none, pass, log"
SecRule TX:counter "@eq 3" "id:3, phase:2, t:none, pass, log"
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

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Test if CRS like chain action works with multiphase evaluation",
		Enabled:     true,
		Name:        "chains_multiphase_crs_920250.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "chains",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/crs_chain_multi%c0",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 920250},
							NonTriggeredRules: []int{11, 12},
							Interruption: &profile.ExpectedInterruption{
								Status: 403,
								Data:   "",
								RuleID: 920250,
								Action: "deny",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/crs_chain_multi",
							Headers: map[string]string{
								"Content-Type": "application/x-www-form-urlencoded"},
							Data: "test=%c0",
						},
						Output: profile.ExpectedOutput{
							// We expect that the chain is evaluated on both phase 1 and 2, but now only at phase 2 it matches
							TriggeredRules:    []int{1, 11, 920250},
							NonTriggeredRules: []int{12},
							Interruption: &profile.ExpectedInterruption{
								Status: 403,
								Data:   "",
								RuleID: 920250,
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

SecAction "id:1, phase:1, pass, setvar:'tx.CRS_VALIDATE_UTF8_ENCODING=1'"
SecRule TX:CRS_VALIDATE_UTF8_ENCODING "@eq 1" \
    "id:920250,\
    phase:2,\
    deny,\
	status:403,\
    t:none,\
    chain"
    SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES "@validateUtf8Encoding" \
        "setvar:'tx.score=+1'"
SecAction "id:11, phase:1, t:none, pass, log"
SecAction "id:12, phase:2, t:none, pass, log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Test if CRS like chain action works with multiphase evaluation",
		Enabled:     true,
		Name:        "chains_multiphase_crs_931130.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "931130",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?x=ftp://foo.bar",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{931130},
							// Rules 11 and 12 are not triggered, therefore 931130 has denied the request at phase 1
							NonTriggeredRules: []int{11, 12},
							Interruption: &profile.ExpectedInterruption{
								Status: 403,
								Data:   "",
								RuleID: 931130,
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
							Data: "x=https://example.com:1234/",
						},
						Output: profile.ExpectedOutput{
							// We expect that the chain is evaluated on both phase 1 and 2, but now only at phase 2 it matches
							TriggeredRules:    []int{11, 931130},
							NonTriggeredRules: []int{12},
							Interruption: &profile.ExpectedInterruption{
								Status: 403,
								Data:   "",
								RuleID: 931130,
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

SecRule ARGS "@rx (?i)(?:(?:url|jar):)?(?:a(?:cap|f[ps]|ttachment)|b(?:eshare|itcoin|lob)|c(?:a(?:llto|p)|id|vs|ompress.(?:zlib|bzip2))|d(?:a(?:v|ta)|ict|n(?:s|tp))|e(?:d2k|xpect)|f(?:(?:ee)?d|i(?:le|nger|sh)|tps?)|g(?:it|o(?:pher)?|lob)|h(?:323|ttps?)|i(?:ax|cap|(?:ma|p)ps?|rc[6s]?)|ja(?:bbe)?r|l(?:dap[is]?|ocal_file)|m(?:a(?:ilto|ven)|ms|umble)|n(?:e(?:tdoc|ws)|fs|ntps?)|ogg|p(?:aparazzi|h(?:ar|p)|op(?:2|3s?)|r(?:es|oxy)|syc)|r(?:mi|sync|tm(?:f?p)?|ar)|s(?:3|ftp|ips?|m(?:[bs]|tps?)|n(?:ews|mp)|sh(?:2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?)?|vn(?:\+ssh)?)|t(?:e(?:amspeak|lnet)|ftp|urns?)|u(?:dp|nreal|t2004)|v(?:entrilo|iew-source|nc)|w(?:ebcal|ss?)|x(?:mpp|ri)|zip)://(?:[^@]+@)?([^/]*)" \
    "id:931130, phase:2, deny, status:403, t:none,\
    setvar:'tx.rfi_parameter_%{MATCHED_VAR_NAME}=.%{tx.1}',\
    chain"
    SecRule TX:/rfi_parameter_.*/ "!@endsWith .%{request_headers.host}" \
        "setvar:'tx.inbound_anomaly_score_pl2=+1'"

SecAction "id:11, phase:1, t:none, pass, log"
SecAction "id:12, phase:2, t:none, pass, log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Test if CRS like chain action works with multiphase evaluation",
		Enabled:     true,
		Name:        "chains_multiphase_crs_933120.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "933120",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test?var=opcache.jit_max_polymorphic_calls%3d10we",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{933120},
							// Rules 11 and 12 are not triggered, therefore 933120 has denied the request at phase 1
							NonTriggeredRules: []int{11, 12},
							Interruption: &profile.ExpectedInterruption{
								Status: 403,
								Data:   "",
								RuleID: 933120,
								Action: "deny",
							},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:     "/",
							Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
							Data:    "var=opcache.jit_max_polymorphic_calls%3d50",
						},
						Output: profile.ExpectedOutput{
							// We expect that the chain is evaluated on both phase 1 and 2, but now only at phase 2 it matches
							TriggeredRules:    []int{11, 933120},
							NonTriggeredRules: []int{12},
							Interruption: &profile.ExpectedInterruption{
								Status: 403,
								Data:   "",
								RuleID: 933120,
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

# for test purposes moved to @pm with just a couple of entries
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@pm allow_url_fopen allow_url_include opcache.jit_max_polymorphic_calls" \
    "id:933120, phase:2, deny, status:403, t:none,t:normalisePath,\
    setvar:'tx.933120_tx_0=%{tx.0}',\
    chain"
    SecRule MATCHED_VARS "@pm =" \
        "capture,\
        setvar:'tx.php_injection_score=+1'"

SecAction "id:11, phase:1, t:none, pass, log"
SecAction "id:12, phase:2, t:none, pass, log"
`,
})
