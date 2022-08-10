package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.ProfileMeta{
		Author:      "jptosso",
		Description: "Test if the macro expansions work",
		Enabled:     true,
		Name:        "macroexpansion.yaml",
	},
	Tests: []profile.ProfileTest{
		{
			Title: "macroexpansions",
			Stages: []profile.ProfileStage{
				{
					Stage: profile.ProfileSubStage{
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{100, 150, 200},
							NonTriggeredRules: []int{901500},
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id:1,pass,setvar:'tx.inbound_anomaly_score_threshold=5',setvar:'tx.paranoia_level=1'"

SecRule TX:inbound_anomaly_score_threshold "@eq 5" "id:100,log,pass"

SecRule TX:inbound_anomaly_score_threshold "@eq %{tx.inbound_anomaly_ScorE_threshold}" "id:150,log,pass"

SecRule TX:paranoia_level "@eq 1" "id:200,log,pass"

SecRule TX:executing_paranoia_level "@lt %{tx.paranoia_level}" "id:901500,phase:1,log"
`,
})
