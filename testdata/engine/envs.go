package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.ProfileMeta{
		Author:      "jptosso",
		Description: "Test if the env work",
		Enabled:     true,
		Name:        "direcenvstives.yaml",
	},
	Tests: []profile.ProfileTest{
		{
			Title: "envs",
			Stages: []profile.ProfileStage{
				{
					Stage: profile.ProfileSubStage{
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id:1, phase:1, setenv:test=123, log"
SecRule ENV:test "@eq 123" "id:2, phase:1, log"
`,
})
