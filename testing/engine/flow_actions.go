// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Test if flow actions are working with both the Engine On and DetectionOnly mode, only by parent rules",
		Enabled:     true,
		Name:        "flow_actions.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "flaw_actions",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 4},
							NonTriggeredRules: []int{2, 3},
						},
					},
				},
			},
		},
	},
	Rules: `
	SecRuleEngine DetectionOnly
	SecRule REQUEST_URI "@unconditionalMatch" "id:1,phase:1,pass,log,skipAfter:END-REPORTING"
	SecAction "id:2,phase:1,deny,status:403,log,msg:'Should not be triggered, being skipped by skipAfter of rule 1'"
	SecMarker "END-REPORTING"

	SecRule REQUEST_URI "@unconditionalMatch" "id:3,phase:2,pass,log,skipAfter:END,chain"
	SecRule REQUEST_URI "@rx /UrlThatWillNotMatch" "id:3,phase:2,pass,log"
	SecAction "id:4,phase:2,deny,status:403,log,msg:'Should match because rule 3 should not be triggered, not being the whole chain matched'"
	SecMarker "END"
`,
})
