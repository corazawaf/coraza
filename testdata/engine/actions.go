package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.ProfileMeta{
		Author:      "jptosso",
		Description: "Test if the actions work",
		Enabled:     true,
		Name:        "actions.yaml",
	},
	Tests: []profile.ProfileTest{
		{
			Title: "actions",
			Stages: []profile.ProfileStage{
				{
					Stage: profile.ProfileSubStage{
						Input: profile.ProfileStageInput{
							URI: "/%FFindex.html?test=test1",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{3, 5, 7, 10},
							NonTriggeredRules: []int{2, 4, 6, 8, 9, 920271},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule REMOTE_ADDR "@unconditionalMatch" "id: 3, ctl:ruleRemoveById=4, log"
SecAction "id: 4, log, pass"
SecAction "id: 5, log, pass"

SecAction "id:6, pass, log, chain"
  SecRule REMOTE_ADDR "1234" ""

SecAction "id:7, pass, log, chain, skip:2"
  SecRule REMOTE_ADDR "@unconditionalMatch" ""

SecAction "id: 8, log, pass"
SecAction "id: 9, log, pass"

SecAction "id: 10, log, pass"

SecRule REQUEST_URI "@validateByteRange 9,10,13,32-126,128-255" "id:920271,phase:2,log,block,t:none,t:urlDecodeUni"
`,
})
