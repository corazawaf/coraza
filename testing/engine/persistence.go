// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if persistence works",
		Enabled:     true,
		Name:        "persistence.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "persistence",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test1",
							Headers: map[string]string{
								"ghi":    "pineapple",
								"cookie": "session=test;",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
		{
			Title: "persistence",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test2",
							Headers: map[string]string{
								"ghi":    "pineapple",
								"cookie": "session=test;",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 3},
						},
					},
				},
			},
		},
	},
	Rules: `
SecPersistenceEngine default
SecAction "id:1,phase:1,initcol:session=%{REQUEST_COOKIES.session},pass,nolog"
SecRule REQUEST_URI "test1" "id:2,phase:2,pass,nolog,setvar:session.test=1"
SecRule REQUEST_URI "test2" "id:3,phase:2,pass,nolog,chain"
	SecRule SESSION:test "1" "log"
`,
})
