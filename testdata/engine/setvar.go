package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.ProfileMeta{
		Author:      "jptosso",
		Description: "Test if the setvar action work",
		Enabled:     true,
		Name:        "setvar.yaml",
	},
	Tests: []profile.ProfileTest{
		{
			Title: "setvar",
			Stages: []profile.ProfileStage{
				{
					Stage: profile.ProfileSubStage{
						Input: profile.ProfileStageInput{
							URI: "/fields?name=foo&var=foo&var=foo2",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{920271},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule ARGS_NAMES "@rx ." \
	"id:921170,\
	nolog,\
	setvar:'TX.paramcounter_%{MATCHED_VAR_NAME}=+1'"

SecRule TX:/paramcounter_/ "@eq 2" "id:920271,log"
`,
})
