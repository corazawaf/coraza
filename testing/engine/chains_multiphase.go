// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.rule.multiphase_evaluation
// +build coraza.rule.multiphase_evaluation

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Test if the chain action works with multiphase evaluation specific tests",
		Enabled:     true,
		Name:        "chains_multiphase.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "chains",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:     "/chain_phase2",
							Method:  "POST",
							Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
							Data:    "chain_phase2",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{10},
							NonTriggeredRules: []int{11, 12, 13},
						},
					},
				},
			},
		},
	},
	Rules: `
SecDebugLogLevel 5
SecRequestBodyAccess On
SecRule REQUEST_URI "/chain_phase2" "id:10, phase:2, t:none, log, setvar:'tx.set1=1',chain"
	SecRule REQUEST_BODY "chain_phase2" "setvar:'tx.set2=2',chain"
		SecRule REQUEST_BODY "chain_phase2" "setvar:'tx.set3=3'"
SecRule REQUEST_URI "/chain_phase2" "id:11, phase:3, t:none, log, chain"
	SecRule TX:set1 "!@eq 1" "deny"
SecRule REQUEST_URI "/chain_phase2" "id:12, phase:3, t:none, log, chain"
	SecRule TX:set1 "!@eq 2" "deny"
SecRule REQUEST_URI "/chain_phase2" "id:13, phase:3, t:none, log, chain"
	SecRule TX:set1 "!@eq 3" "deny"
`,
})
