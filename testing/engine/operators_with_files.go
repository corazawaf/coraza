// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if operators with files works",
		Enabled:     true,
		Name:        "operators_with_files.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "owf",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/?ghi=cdf",
							Headers: map[string]string{
								"ghi":    "pineapple",
								"cookie": "ghi=cfg;def=ghi",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 3, 5, 10},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule ARGS_NAMES "@pmFromFile pmFromFile-01.dat" "id:1,log"
SecRule REQUEST_COOKIES:def "@pmFromFile pmFromFile-01.dat" "id:3,log"
SecRule REQUEST_COOKIES_NAMES "@pmFromFile pmFromFile-01.dat" "id:5,log"
SecRule REQUEST_HEADERS_NAMES "@pmFromFile pmFromFile-01.dat" "id:10,log"
`,
})
