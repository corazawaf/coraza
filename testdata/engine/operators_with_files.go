package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.ProfileMeta{
		Author:      "jptosso",
		Description: "Test if operators with files works",
		Enabled:     true,
		Name:        "operators_with_files.yaml",
	},
	Tests: []profile.ProfileTest{
		{
			Title: "owf",
			Stages: []profile.ProfileStage{
				{
					Input: profile.ProfileStageInput{
						URI: "/?ghi=cdf",
						Headers: map[string]string{
							"ghi":    "pineapple",
							"cookie": "ghi=cfg;def=ghi",
						},
					},
					Output: profile.ExpectedOutput{
						TriggeredRules: []int{1, 3, 5, 10},
					},
				},
			},
		},
	},
	Rules: `
SecRule ARGS_NAMES "@pmFromFile operators/op/pmFromFile-01.dat" "id:1,log"
SecRule REQUEST_COOKIES:def "@pmFromFile operators/op/pmFromFile-01.dat" "id:3,log"
SecRule REQUEST_COOKIES_NAMES "@pmFromFile operators/op/pmFromFile-01.dat" "id:5,log"
SecRule REQUEST_HEADERS_NAMES "@pmFromFile operators/op/pmFromFile-01.dat" "id:10,log"
`,
})
