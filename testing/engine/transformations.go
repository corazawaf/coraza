// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"crypto/fips140"

	"github.com/corazawaf/coraza/v3/testing/profile"
)

// Rules 777 and 778 rely on t:md5, which is unavailable when the binary runs in FIPS 140-3 mode:
// the transformation errors out, the untransformed value reaches the operator, and the rules no
// longer match.
//
// These are functions rather than an init() because package-level variables are initialized before
// init() runs, so an init() would be too late to affect the registered profile below.
func md5TriggeredRules() []int {
	if fips140.Enabled() {
		return []int{942101}
	}
	return []int{777, 778, 942101}
}

func md5NonTriggeredRules() []int {
	if fips140.Enabled() {
		return []int{777, 778}
	}
	return nil
}

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
							TriggeredRules:    md5TriggeredRules(),
							NonTriggeredRules: md5NonTriggeredRules(),
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
