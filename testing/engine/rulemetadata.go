// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the rule metadata",
		Enabled:     true,
		Name:        "rulemetadata.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "rulemetadata",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id:1, log, severity:5"
SecRule HIGHEST_SEVERITY "@eq 5" "id:2, log"
`,
})
