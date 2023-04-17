// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Test if operators with datasets works",
		Enabled:     true,
		Name:        "operators_with_datasets.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "operators with dataset",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/uri2",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
	},
	Rules: `
	SecDataset pm_dataset ` + "`" + `
	uri1
	uri2
	` + "`" + `
	SecDataset ip_dataset ` + "`" + `
	127.0.0.1
	` + "`" + `
SecRule REQUEST_URI "@pmFromDataset pm_dataset" "id:1,log,phase:1,pass,msg:'Match pm_dataset'"
SecRule REMOTE_ADDR "@ipMatchFromDataset ip_dataset" "id:2,log,phase:1,pass,msg:'Match ip_dataset'"
`,
})
