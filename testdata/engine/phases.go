// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the 5 transaction phase are being executed",
		Enabled:     true,
		Name:        "phases.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "phases",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								2,
								3,
								4,
								// 5,
								6,
							},
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id: 2, phase: 1, log, pass"
SecAction "id: 3, phase: 2, log, pass"
SecAction "id: 4, phase: 3, log, pass"
#SecAction "id: 5, phase: 4, log, pass" Won't work as it requires a response body
SecAction "id: 6, phase: 5, log, pass"
`,
})
