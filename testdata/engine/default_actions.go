package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.ProfileMeta{
		Author:      "jptosso",
		Description: "Test if the default_actions work",
		Enabled:     true,
		Name:        "default_actions.yaml",
	},
	Tests: []profile.ProfileTest{
		{
			Title: "default_actions",
			Stages: []profile.ProfileStage{
				{
					Stage: profile.ProfileSubStage{
						Input: profile.ProfileStageInput{
							URI: "/%FFindex.html?test=test1",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								1,
								2,
								3,
								4,
								5,
								6,
								7,
								8,
								9,
								10,
							},
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id:1, phase:1, pass"
SecAction "id:2, phase:2, pass"
SecAction "id:3, phase:3, pass"
SecAction "id:4, phase:4, pass"
SecAction "id:5, phase:5, pass"
SecAction "id:6, phase:1, pass"
SecAction "id:7, phase:2, pass"
SecAction "id:8, phase:3, pass"
SecAction "id:9, phase:4, pass"
SecAction "id:10, phase:5, pass"
`,
})
