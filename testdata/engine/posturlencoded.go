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
							Headers: map[string]string{
								"content-type": "application/x-www-form-urlencoded",
							},
							Data: "test=123",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{4445, 456},
							NonTriggeredRules: []int{200002},
						},
					},
				},
				{
					Stage: profile.ProfileSubStage{
						Input: profile.ProfileStageInput{
							URI:    "/",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{200002},
						},
					},
				},
				{
					Stage: profile.ProfileSubStage{
						Input: profile.ProfileStageInput{
							URI:    "/case2",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/x-www-form-urlencoded",
							},
							Data: "var%3d%20@.%3d%20%28%20SELECT",
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
SecRule ARGS:test "123" "phase:2, id:4445,block,log"
SecRule REQUEST_BODY "test=" "phase:2, id:456, log"

SecRule REQBODY_ERROR "!@eq 0" \
  "id:'200002', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"

SecRule REQUEST_URI "case2" "id:100, chain, log, phase:2"
		SecRule ARGS_NAMES "SELECT" ""
`,
})
