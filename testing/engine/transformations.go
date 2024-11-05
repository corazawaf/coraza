// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the transformations work",
		Enabled:     true,
		Name:        "transformations.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "transformations",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/unittests@coreruleset.org\"%20sleep(10.to_i)%20",
							Headers: map[string]string{
								"test":  "1234",
								"test2": "456",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{777, 778, 942101},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule REQUEST_HEADERS:test "81dc9bdb52d04dc20036dbd8313ed055" "id:777, phase:1, log, multiMatch, t:none, t:md5, t:hexEncode"
SecRule REQUEST_HEADERS:test2 "@eq 32" "id:778, phase:1, log, t:none, t:md5, t:hexEncode, t:length"

SecRule REQUEST_BASENAME "@gt 10" "id:942101,phase:1,block,capture,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,t:length, log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "m4tteoP",
		Description: "Test if multiMatch does not matches multiple time the same unchanged variable",
		Enabled:     true,
		Name:        "transformations_multimatch.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "transformations_multimatch",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/this_very_specific_uri",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 11},
						},
					},
				},
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/this_very_specific_URI",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{2, 12},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule REQUEST_URI "@rx this_very_specific_uri" "id:1, phase:1, pass, log, t:urlDecodeUni, t:removeNulls, t:lowercase,\
multiMatch, setvar:'tx.matched_times=+1'"

SecRule REQUEST_URI "@rx this_very_specific" \
    "id:2, phase:1, pass, log,\
    t:lowercase,\
    multiMatch,\
    setvar:'tx.matched_times2=+1'"

SecRule TX:matched_times "@eq 1" "id:11, phase:1, pass, log, t:none"
SecRule TX:matched_times2 "@eq 2" "id:12, phase:1, pass, log, t:none"
`,
})
