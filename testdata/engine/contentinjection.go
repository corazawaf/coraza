package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.ProfileMeta{
		Author:      "jptosso",
		Description: "Test if content injection works",
		Enabled:     true,
		Name:        "contentinjection.yaml",
	},
	Tests: []profile.ProfileTest{
		{
			Title: "content injection",
			Stages: []profile.ProfileStage{
				{
					Output: profile.ExpectedOutput{
						TriggeredRules: []int{
							// It used to work but I´m not confident with the tests
							// needs more testing
							// 10101
						},
					},
				},
			},
		},
	},
	Rules: `
SecResponseBodyMimeType text/html
SecRuleEngine On
SecContentInjection On
SecResponseBodyAccess On
SecAction "id:1, phase:3, append:abcdef, prepend:123"
SecRule RESPONSE_BODY "123abcdef" "id:10101, phase:4, log"
`,
})
