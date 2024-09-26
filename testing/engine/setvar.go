// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/redwanghb/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the setvar action work",
		Enabled:     true,
		Name:        "setvar.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "setvar",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
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

SecRule TX:/paramcounter_.*/ "@eq 2" "id:920271,log"
`,
})
