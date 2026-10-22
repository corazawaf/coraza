// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import "github.com/corazawaf/coraza/v3/testing/profile"

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "adilalperenciftci",
		Description: "SecRequestBodyNoFilesLimit rejects non-file bodies only above the configured limit",
		Enabled:     true,
		Name:        "request_body_no_files_limit_reject.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "body below no-files limit",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{
					URI:     "/",
					Method:  "POST",
					Headers: map[string]string{"Content-Type": "application/octet-stream"},
					Data:    "payload=1234567",
				},
				Output: profile.ExpectedOutput{
					TriggeredRules:    []int{10},
					NonTriggeredRules: []int{11},
				},
			}}},
		},
		{
			Title: "body equal to no-files limit",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{
					URI:     "/",
					Method:  "POST",
					Headers: map[string]string{"Content-Type": "application/octet-stream"},
					Data:    "payload=12345678",
				},
				Output: profile.ExpectedOutput{
					TriggeredRules:    []int{11},
					NonTriggeredRules: []int{10},
				},
			}}},
		},
		{
			Title: "body above no-files limit",
			Stages: []profile.Stage{{Stage: profile.SubStage{
				Input: profile.StageInput{
					URI:     "/",
					Method:  "POST",
					Headers: map[string]string{"Content-Type": "application/octet-stream"},
					Data:    "payload=123456789",
				},
				Output: profile.ExpectedOutput{
					NonTriggeredRules: []int{10, 11},
					Interruption:      &profile.ExpectedInterruption{Status: 413, Action: "deny"},
				},
			}}},
		},
	},
	Rules: `
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 64
SecRequestBodyNoFilesLimit 16
SecRequestBodyLimitAction Reject
SecAction "id:1,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"
SecRule ARGS_POST:payload "@streq 1234567" "id:10,phase:2,pass,log"
SecRule ARGS_POST:payload "@streq 12345678" "id:11,phase:2,pass,log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "adilalperenciftci",
		Description: "An unset SecRequestBodyNoFilesLimit preserves existing request-body processing",
		Enabled:     true,
		Name:        "request_body_no_files_limit_unset.yaml",
	},
	Tests: []profile.Test{{
		Title: "unconfigured no-files limit",
		Stages: []profile.Stage{{Stage: profile.SubStage{
			Input: profile.StageInput{
				URI:     "/",
				Method:  "POST",
				Headers: map[string]string{"Content-Type": "application/octet-stream"},
				Data:    "payload=123456789012345678901234",
			},
			Output: profile.ExpectedOutput{TriggeredRules: []int{20}},
		}}},
	}},
	Rules: `
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 64
SecAction "id:1,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"
SecRule ARGS_POST:payload "@streq 123456789012345678901234" "id:20,phase:2,pass,log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "adilalperenciftci",
		Description: "SecRequestBodyNoFilesLimit does not read a body when body access is disabled",
		Enabled:     true,
		Name:        "request_body_no_files_limit_access_off.yaml",
	},
	Tests: []profile.Test{{
		Title: "request body access disabled",
		Stages: []profile.Stage{{Stage: profile.SubStage{
			Input: profile.StageInput{
				URI:     "/",
				Method:  "POST",
				Headers: map[string]string{"Content-Type": "application/octet-stream"},
				Data:    "payload=123456789012345678901234",
			},
			Output: profile.ExpectedOutput{NonTriggeredRules: []int{30}},
		}}},
	}},
	Rules: `
SecRuleEngine On
SecRequestBodyAccess Off
SecRequestBodyLimit 64
SecRequestBodyNoFilesLimit 16
SecRule REQBODY_ERROR "!@eq 0" "id:30,phase:2,pass,log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "adilalperenciftci",
		Description: "ProcessPartial exposes only the inspected no-files prefix in DetectionOnly mode",
		Enabled:     true,
		Name:        "request_body_no_files_limit_detection_only.yaml",
	},
	Tests: []profile.Test{{
		Title: "detection-only partial body",
		Stages: []profile.Stage{{Stage: profile.SubStage{
			Input: profile.StageInput{
				URI:     "/",
				Method:  "POST",
				Headers: map[string]string{"Content-Type": "application/octet-stream"},
				Data:    "payload=123456789",
			},
			Output: profile.ExpectedOutput{TriggeredRules: []int{40, 41}},
		}}},
	}},
	Rules: `
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyLimit 64
SecRequestBodyNoFilesLimit 16
SecRequestBodyLimitAction ProcessPartial
SecAction "id:1,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"
SecRule REQBODY_ERROR "@eq 1" "id:40,phase:2,pass,log"
SecRule ARGS_POST:payload "@streq 12345678" "id:41,phase:2,pass,log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "adilalperenciftci",
		Description: "A no-files limit at or above the overall body limit is disabled for multipart processing",
		Enabled:     true,
		Name:        "request_body_no_files_limit_disabled.yaml",
	},
	Tests: []profile.Test{{
		Title: "disabled multipart no-files limit publishes parser metadata",
		Stages: []profile.Stage{{Stage: profile.SubStage{
			Input: profile.StageInput{
				URI:     "/",
				Method:  "POST",
				Headers: map[string]string{"Content-Type": "multipart/form-data; boundary=b"},
				Data: "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"evil.php\"\r\n" +
					"Content-Transfer-Encoding: quoted-printable\r\n\r\n\x00\r\n--b--\r\n",
			},
			Output: profile.ExpectedOutput{TriggeredRules: []int{50}},
		}}},
	}},
	Rules: `
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 1024
SecRequestBodyNoFilesLimit 2048
SecRequestBodyLimitAction Reject
SecRule MULTIPART_FILENAME "@streq evil.php" "id:50,phase:2,pass,log"
`,
})
