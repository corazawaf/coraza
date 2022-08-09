package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.ProfileMeta{
		Author:      "jptosso",
		Description: "Test if the headers parsers work",
		Enabled:     true,
		Name:        "headers_parser.yaml",
	},
	Tests: []profile.ProfileTest{
		{
			Title: "envs",
			Stages: []profile.ProfileStage{
				{
					Stage: profile.ProfileSubStage{
						Input: profile.ProfileStageInput{
							Method: "GET",
							Headers: map[string]string{
								"test":              "456",
								"Transfer-Encoding": "chunked",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 5, 920171},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule REQUEST_HEADERS:test "456" "phase:1,t:none,log,id:1,msg:'test'"
SecRule REQUEST_HEADERS_NAMES "test" "log,id:5"

SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "id:920171,phase:1, log,chain"
  SecRule &REQUEST_HEADERS:Transfer-Encoding "!@eq 0" ""
`,
})
