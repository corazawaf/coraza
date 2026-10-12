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
			// %{rule.msg} and %{rule.logdata} are expanded at match time, so
			// setvar in the matching rule sees the expanded value.
			Title: "rule.msg and rule.logdata expanded in setvar",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{URI: "/?id=42"},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{300, 301, 302, 304},
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id:1,pass,setvar:'tx.inbound_anomaly_score_threshold=5',setvar:'tx.blocking_paranoia_level=1'"

SecRule ARGS:id "@rx ^\d+$" "id:300,phase:1,log,pass,msg:'id is %{MATCHED_VAR}',logdata:'arg %{MATCHED_VAR_NAME}',setvar:'tx.rule_msg=%{rule.msg}',setvar:'tx.rule_logdata=%{rule.logdata}'"
SecRule TX:rule_msg "@streq id is 42" "id:301,phase:1,log,pass"
SecRule TX:rule_logdata "@rx ^arg ARGS(_GET)?:id$" "id:302,phase:1,log,pass"
SecAction "id:303,log,pass,msg:'score is %{tx.inbound_anomaly_score_threshold}',setvar:'tx.action_msg=%{rule.msg}'"
SecRule TX:action_msg "@streq score is 5" "id:304,log,pass"

SecRule TX:inbound_anomaly_score_threshold "@eq 5" "id:100,log,pass"

SecRule TX:inbound_anomaly_score_threshold "@eq %{tx.inbound_anomaly_ScorE_threshold}" "id:150,log,pass"

SecRule TX:blocking_paranoia_level "@eq 1" "id:200,log,pass"

SecRule TX:executing_paranoia_level "@lt %{tx.blocking_paranoia_level}" "id:901500,phase:1,log"
`,
})
