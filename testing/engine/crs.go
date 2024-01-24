// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v4/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "This is a mix of many tests used to make fixes for CRS",
		Enabled:     true,
		Name:        "crs.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "crs",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							Method: "GET",
							URI:    "/test.php?id=12345",
							Headers: map[string]string{
								"User-Agent":     "ModSecurity CRS 3 Tests",
								"Host":           "localhost",
								"Content-Type":   "application/x-www-form-urlencoded",
								"content-length": "4",
								"Range":          "bytes=1-10,11-20,21-30,31-40,41-50,51-60",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{920170, 920200},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" \
	"id:920170,\
	phase:1,\
	log,\
	chain"
	SecRule REQUEST_HEADERS:Content-Length "!@rx ^0?$" \
		"t:none,\
		setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

SecRule REQUEST_HEADERS:Range|REQUEST_HEADERS:Request-Range "@rx ^bytes=(?:(?:\d+)?-(?:\d+)?\s*,?\s*){6}" \
	"id:920200,\
	phase:1,\
	log,\
	chain"
	SecRule REQUEST_BASENAME "!@endsWith .pdf" \
		"setvar:'tx.anomaly_score_pl2=+%{tx.warning_anomaly_score}'"    
`,
})
