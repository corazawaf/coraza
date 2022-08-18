// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
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
