// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the macro expansions work",
		Enabled:     true,
		Name:        "macroexpansion.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "macroexpansions",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{100, 150, 200},
							NonTriggeredRules: []int{901500},
						},
					},
				},
			},
		},
		{
			Title: "an unset variable in msg and in an operator expands to the empty string",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{301, 302},
							LogContains:    "direct=[]",
							NoLogContains:  "tx.non_existent",
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id:1,pass,setvar:'tx.inbound_anomaly_score_threshold=5',setvar:'tx.blocking_paranoia_level=1'"

SecRule TX:inbound_anomaly_score_threshold "@eq 5" "id:100,log,pass"

SecRule TX:inbound_anomaly_score_threshold "@eq %{tx.inbound_anomaly_ScorE_threshold}" "id:150,log,pass"

SecRule TX:blocking_paranoia_level "@eq 1" "id:200,log,pass"

SecRule TX:executing_paranoia_level "@lt %{tx.blocking_paranoia_level}" "id:901500,phase:1,log"

SecRule REQUEST_METHOD "@rx ." "id:301,phase:1,pass,log,msg:'direct=[%{tx.non_existent}]'"
SecRule REQUEST_METHOD "@streq %{tx.non_existent}GET" "id:302,phase:1,pass,log"
`,
})
