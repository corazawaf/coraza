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
			// tag supports macro expansion, resolved per match (#1118)
			Title: "tags are macro expanded",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Headers: map[string]string{"X-Request-Id": "abc123"},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{300},
							LogContains:    `[tag "static"] [tag "request-id:abc123"]`,
							NoLogContains:  `%{REQUEST_HEADERS.x-request-id}`,
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id:1,pass,setvar:'tx.inbound_anomaly_score_threshold=5',setvar:'tx.blocking_paranoia_level=1'"

SecRule REQUEST_HEADERS:X-Request-Id "@rx ." "id:300,phase:1,log,pass,tag:'static',tag:'request-id:%{REQUEST_HEADERS.x-request-id}'"

SecRule TX:inbound_anomaly_score_threshold "@eq 5" "id:100,log,pass"

SecRule TX:inbound_anomaly_score_threshold "@eq %{tx.inbound_anomaly_ScorE_threshold}" "id:150,log,pass"

SecRule TX:blocking_paranoia_level "@eq 1" "id:200,log,pass"

SecRule TX:executing_paranoia_level "@lt %{tx.blocking_paranoia_level}" "id:901500,phase:1,log"
`,
})
