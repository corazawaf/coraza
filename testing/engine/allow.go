// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "fzipi",
		Description: "Test if the allow action works",
		Enabled:     true,
		Name:        "allow.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "actions",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "GET",
							URI:    "/?key=value&key=other_value",
							Data:   "monte=video",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								1,
							},
							NonTriggeredRules: []int{
								2,
							},
						},
					},
				},
			},
		},
	},
	Rules: `
SecDebugLogLevel 5
SecAction "id:1,phase:1,allow,msg:'ALLOWED'"
SecAction "id:2,phase:1,deny,msg:'DENIED'"
`,
})
