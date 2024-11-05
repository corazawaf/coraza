// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the directives work",
		Enabled:     true,
		Name:        "directives.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "directives",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								1,
								2,
								7,
								9,
								9001000,
								9001002,
							},
							NonTriggeredRules: []int{
								4,
								5,
								6,
								8,
								9001001,
							},
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id: 1, log"
SecAction "id: 2, log, skipAfter:test-mark"

SecAction "id: 4, log"
SecAction "id: 5,log"
SecAction "id: 6"

SecMarker test-mark
SecAction "id: 7, log, skipAfter: test-mark3"

SecMarker test-mark2
SecAction "id: 8, log"
SecMarker test-mark3
SecAction "id: 9, log"

SecRule &TX:crs_exclusions_drupal|TX:crs_exclusions_drupal "@eq 0" \
"id:9001000,\
phase:2,\
log, \
skipAfter:END-DRUPAL-RULE-EXCLUSIONS"

SecAction "id: 9001001, log, phase:2"

SecMarker END-DRUPAL-RULE-EXCLUSIONS
SecAction "id: 9001002, log, phase:2"
`,
})
