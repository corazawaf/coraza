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
	},
	Rules: `
SecRule REQUEST_URI "@beginsWith /remove-target" "id:1,phase:1,pass,log,ctl:ruleRemoveTargetByTag=idless-t1;ARGS_GET:idless"
SecRule REQUEST_URI "@beginsWith /remove-rule" "id:2,phase:1,pass,log,ctl:ruleRemoveByTag=idless-t1"
SecRule ARGS_GET:idless "@rx evil" "phase:1,pass,nolog,tag:'idless-t1',setvar:'tx.idless_tagged=1'"
SecRule ARGS_GET:idless "@rx evil" "phase:1,pass,nolog,setvar:'tx.idless_untagged=1'"
SecRule TX:idless_untagged "@eq 1" "id:391,phase:1,pass,log"
SecRule TX:idless_tagged "@eq 1" "id:392,phase:1,pass,log"
`,
})
