// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

// The sanitise* actions mask values in the audit log only. NoAuditLogContains
// renders the record with every built-in formatter, so these tests also check
// that redaction happens before any formatter sees the data.
var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "ayushsinha322",
		Description: "sanitise* actions mask arguments and headers in the audit log",
		Enabled:     true,
		Name:        "sanitise.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "query argument is masked and still inspected",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{URI: "/login?user=bob&password=hunter22"},
				Output: profile.ExpectedOutput{
					TriggeredRules:     []int{10},
					AuditLogContains:   "password=********",
					NoAuditLogContains: "hunter22",
				},
			}}},
		},
		{
			Title: "other arguments stay visible",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{URI: "/login?user=bob&password=hunter22"},
				Output: profile.ExpectedOutput{
					AuditLogContains: "user=bob",
				},
			}}},
		},
		{
			Title: "rule messages and log data are masked",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{URI: "/login?password=hunter22"},
				Output: profile.ExpectedOutput{
					// Multiphase evaluation reports the match as ARGS_GET, so the
					// variable name is not pinned.
					AuditLogContains: `[data "Matched Data: ******** found within ARGS`,
				},
			}}},
		},
		{
			Title: "error log keeps the original value as in ModSecurity",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{URI: "/login?password=hunter22"},
				Output: profile.ExpectedOutput{
					LogContains: "Matched Data: hunter22 found within ARGS",
				},
			}}},
		},
		{
			Title: "url-encoded body argument is masked",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{
					URI:    "/login",
					Method: "POST",
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
					},
					Data: "user=bob&password=hunter33",
				},
				Output: profile.ExpectedOutput{
					AuditLogContains:   "user=bob&password=********",
					NoAuditLogContains: "hunter33",
				},
			}}},
		},
		{
			Title: "json body argument is masked",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{
					URI:    "/login",
					Method: "POST",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Data: `{"user":"bob","password":"jsonpw77"}`,
				},
				Output: profile.ExpectedOutput{
					AuditLogContains:   `"password":"********"`,
					NoAuditLogContains: "jsonpw77",
				},
			}}},
		},
		{
			Title: "argument names are compared case-insensitively",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{URI: "/?PassWord=caseval1"},
				Output: profile.ExpectedOutput{
					AuditLogContains:   "PassWord=********",
					NoAuditLogContains: "caseval1",
				},
			}}},
		},
		{
			Title: "repeated arguments are all masked",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{URI: "/?password=first1&password=second2"},
				Output: profile.ExpectedOutput{
					AuditLogContains:   "password=******&password=*******",
					NoAuditLogContains: "second2",
				},
			}}},
		},
		{
			Title: "request header is masked",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{
					URI:     "/",
					Headers: map[string]string{"Authorization": "Bearer tok3nvalue"},
				},
				Output: profile.ExpectedOutput{
					AuditLogContains:   "authorization: *****************",
					NoAuditLogContains: "tok3nvalue",
				},
			}}},
		},
		{
			Title: "response header is masked",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{URI: "/"},
				Output: profile.ExpectedOutput{
					// The harness sends Output.Headers as the response headers.
					Headers:            map[string]string{"Set-Cookie": "sid=c00kie42"},
					AuditLogContains:   "set-cookie: ************",
					NoAuditLogContains: "c00kie42",
				},
			}}},
		},
		{
			Title: "sanitiseMatched masks the argument found by ARGS_NAMES",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{URI: "/?mysecret=val777&q=plain"},
				Output: profile.ExpectedOutput{
					AuditLogContains:   "mysecret=******&q=plain",
					NoAuditLogContains: "val777",
				},
			}}},
		},
		{
			Title: "sanitiseMatched masks a matched request header",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{
					URI:     "/",
					Headers: map[string]string{"X-Api-Key": "k3y999"},
				},
				Output: profile.ExpectedOutput{
					AuditLogContains:   "x-api-key: ******",
					NoAuditLogContains: "k3y999",
				},
			}}},
		},
		{
			Title: "sanitiseMatched on another variable masks nothing",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{URI: "/item?id=plain42"},
				Output: profile.ExpectedOutput{
					TriggeredRules:   []int{40},
					AuditLogContains: "id=plain42",
				},
			}}},
		},
	},
	Rules: `
SecRuleEngine On
SecRequestBodyAccess On
SecAuditLogParts ABCFHKZ
SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
SecAction "id:2,phase:1,pass,nolog,sanitiseArg:password,sanitiseArg:json.password,sanitiseRequestHeader:Authorization"
SecAction "id:3,phase:3,pass,nolog,sanitiseResponseHeader:Set-Cookie"
SecRule ARGS:password "@beginsWith hunt" "id:10,phase:2,pass,log,msg:'password seen',logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"
SecRule ARGS_NAMES "@contains secret" "id:20,phase:2,pass,nolog,sanitiseMatched"
SecRule REQUEST_HEADERS:X-Api-Key "@rx ." "id:30,phase:1,pass,nolog,sanitiseMatched"
SecRule REQUEST_FILENAME "@streq /item" "id:40,phase:1,pass,log,sanitiseMatched"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "ayushsinha322",
		Description: "without sanitise* actions the audit log keeps the original values",
		Enabled:     true,
		Name:        "sanitise_absent.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "values are logged unchanged",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{
					URI:     "/login?password=visible1",
					Headers: map[string]string{"Authorization": "Bearer visible2"},
				},
				Output: profile.ExpectedOutput{
					AuditLogContains: "password=visible1",
				},
			}}},
		},
	},
	Rules: `
SecRuleEngine On
SecAuditLogParts ABCFHKZ
`,
})
