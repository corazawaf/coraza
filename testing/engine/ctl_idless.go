// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.rule.mandatory_rule_id_check

// Rules without an id cannot load under the mandatory id check.

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "fzipi",
		Description: "ctl removals do not spread across rules without an id",
		Enabled:     true,
		Name:        "ctl_idless.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "ctl removals never apply to rules without an id",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{URI: "/remove-target?idless=evil"},
						Output: profile.ExpectedOutput{
							// Rules without an id cannot be targeted by ctl, so both keep
							// inspecting ARGS_GET:idless (391, 392).
							TriggeredRules: []int{1, 391, 392},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{URI: "/remove-rule?idless=evil"},
						Output: profile.ExpectedOutput{
							// Neither id-less rule is removed (391, 392).
							TriggeredRules: []int{2, 391, 392},
						},
					},
				},
			},
		},
		{
			Title: "ctl removals leave SecMarkers in place",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{URI: "/skip-after?idless=evil"},
						Output: profile.ExpectedOutput{
							// Rule 3 removes the rules tagged idless-t1 and skips to
							// IDLESS_END. The marker has no id either; evaluation must
							// resume there (394) after skipping 393.
							TriggeredRules:    []int{3, 394},
							NonTriggeredRules: []int{393},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{URI: "/skip-zero?idless=evil"},
						Output: profile.ExpectedOutput{
							// Rule 4 removes rule id 0, which no rule has.
							TriggeredRules:    []int{4, 394},
							NonTriggeredRules: []int{393},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{URI: "/skip-range?idless=evil"},
						Output: profile.ExpectedOutput{
							// Rule 5 removes the id range 0-2, which must not reach the marker.
							TriggeredRules:    []int{5, 394},
							NonTriggeredRules: []int{393},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule REQUEST_URI "@beginsWith /remove-target" "id:1,phase:1,pass,log,ctl:ruleRemoveTargetByTag=idless-t1;ARGS_GET:idless"
SecRule REQUEST_URI "@beginsWith /remove-rule" "id:2,phase:1,pass,log,ctl:ruleRemoveByTag=idless-t1"
SecRule ARGS_GET:idless "@rx evil" "phase:1,pass,nolog,tag:'idless-t1',setvar:'tx.idless_tagged=1'"
SecRule ARGS_GET:idless "@rx evil" "phase:1,pass,nolog,setvar:'tx.idless_untagged=1'"
SecRule TX:idless_untagged "@eq 1" "id:391,phase:1,pass,log"
SecRule TX:idless_tagged "@eq 1" "id:392,phase:1,pass,log"
SecRule REQUEST_URI "@beginsWith /skip-after" "id:3,phase:1,pass,log,ctl:ruleRemoveByTag=idless-t1,skipAfter:IDLESS_END"
SecRule REQUEST_URI "@beginsWith /skip-zero" "id:4,phase:1,pass,log,ctl:ruleRemoveById=0,skipAfter:IDLESS_END"
SecRule REQUEST_URI "@beginsWith /skip-range" "id:5,phase:1,pass,log,ctl:ruleRemoveById=0-2,skipAfter:IDLESS_END"
SecRule ARGS_GET:idless "@rx evil" "id:393,phase:1,pass,log"
SecMarker IDLESS_END
SecRule ARGS_GET:idless "@rx evil" "id:394,phase:1,pass,log"
`,
})
