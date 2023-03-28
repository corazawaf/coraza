// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the noon variables work",
		Enabled:     true,
		Name:        "noons.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "noons",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/%FFindex.html?test=test1",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{4},
							NonTriggeredRules: []int{3},
						},
					},
				},
			},
		},
	},
	Rules: `
	SecRule IP:/_/|TIME|USER ".*" "id: 3,  log"
	SecRule &IP "@eq 0" "id: 4,  log, chain"
		SecRule &IP:/_/ "@eq 0" "log"
`,
})
