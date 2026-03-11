// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "fzipi",
		Description: "Test ARGS_RAW, ARGS_GET_RAW, ARGS_POST_RAW, and ARGS_NAMES_RAW collections",
		Enabled:     true,
		Name:        "args_raw.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "ARGS_GET_RAW preserves URL-encoded values",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php?key=%3Cscript%3E&other=hello",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								100, // ARGS_GET_RAW:key matches %3Cscript%3E (raw)
								101, // ARGS_GET:key matches <script> (decoded)
								102, // ARGS_RAW matches %3Cscript%3E (raw, union)
							},
							NonTriggeredRules: []int{
								103, // ARGS_GET_RAW:key does NOT match <script> literally
							},
						},
					},
				},
			},
		},
		{
			Title: "ARGS_POST_RAW preserves URL-encoded POST body values",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/x-www-form-urlencoded",
							},
							Data: "password=Secret%2500&user=admin",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								200, // ARGS_POST_RAW:password matches %2500 (double encoding preserved)
								201, // ARGS_POST:password matches %00 (single decoded)
								202, // ARGS_RAW matches %2500 (raw, union)
							},
							NonTriggeredRules: []int{
								203, // ARGS_POST_RAW:password does NOT match %00 literally
							},
						},
					},
				},
			},
		},
		{
			Title: "ARGS_NAMES_RAW preserves URL-encoded argument names",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php?p%61ram=value",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								300, // ARGS_NAMES_RAW matches p%61ram (raw name)
								301, // ARGS_GET_NAMES matches param (decoded name)
							},
							NonTriggeredRules: []int{
								302, // ARGS_NAMES_RAW does NOT match "param" literally
							},
						},
					},
				},
			},
		},
		{
			Title: "ARGS_GET_RAW preserves plus signs as literal",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php?q=hello+world",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								400, // ARGS_GET_RAW:q contains "+" literal (preserved)
								401, // ARGS_GET:q contains "hello world" (decoded, + becomes space)
							},
							NonTriggeredRules: []int{
								402, // ARGS_GET_RAW:q does NOT match "hello world" (no space decoding)
							},
						},
					},
				},
			},
		},
		{
			Title: "ARGS_GET_NAMES_RAW preserves URL-encoded GET argument names",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php?p%61ram=value&other=hello",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								500, // ARGS_GET_NAMES_RAW matches raw name p%61ram
								501, // ARGS_GET_NAMES matches decoded name param
							},
							NonTriggeredRules: []int{
								502, // ARGS_GET_NAMES_RAW does NOT match decoded "param"
							},
						},
					},
				},
			},
		},
		{
			Title: "ARGS_POST_NAMES_RAW preserves URL-encoded POST argument names",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/x-www-form-urlencoded",
							},
							Data: "p%61ssword=secret&user=admin",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								600, // ARGS_POST_NAMES_RAW matches raw name p%61ssword
								601, // ARGS_POST_NAMES matches decoded name password
							},
							NonTriggeredRules: []int{
								602, // ARGS_POST_NAMES_RAW does NOT match decoded "password"
							},
						},
					},
				},
			},
		},
		{
			Title: "ARGS_GET_RAW handles multiple values for the same key",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php?color=red&color=gr%65en&color=blue",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								700, // ARGS_GET_RAW:color matches "gr%65en" (raw, second value)
								701, // ARGS_GET:color matches "green" (decoded second value)
							},
							NonTriggeredRules: []int{
								702, // ARGS_GET_RAW:color does NOT match decoded "green"
							},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRequestBodyAccess On

# Test 1: ARGS_GET_RAW preserves URL-encoded values
SecRule ARGS_GET_RAW:key "@contains %3Cscript%3E" "id:100,phase:1,pass,log"
SecRule ARGS_GET:key "@contains <script>" "id:101,phase:1,pass,log"
SecRule ARGS_RAW "@contains %3Cscript%3E" "id:102,phase:1,pass,log"
SecRule ARGS_GET_RAW:key "@contains <script>" "id:103,phase:1,pass,log"

# Test 2: ARGS_POST_RAW preserves double encoding
SecRule ARGS_POST_RAW:password "@contains %2500" "id:200,phase:2,pass,log"
SecRule ARGS_POST:password "@rx %00" "id:201,phase:2,pass,log"
SecRule ARGS_RAW "@contains %2500" "id:202,phase:2,pass,log"
SecRule ARGS_POST_RAW:password "@rx %00$" "id:203,phase:2,pass,log"

# Test 3: ARGS_NAMES_RAW preserves encoded names
SecRule ARGS_NAMES_RAW "@contains p%61ram" "id:300,phase:1,pass,log"
SecRule ARGS_GET_NAMES "@streq param" "id:301,phase:1,pass,log"
SecRule ARGS_NAMES_RAW "@streq param" "id:302,phase:1,pass,log"

# Test 4: ARGS_GET_RAW preserves plus signs
SecRule ARGS_GET_RAW:q "@rx \+" "id:400,phase:1,pass,log"
SecRule ARGS_GET:q "@rx hello world" "id:401,phase:1,pass,log"
SecRule ARGS_GET_RAW:q "@rx hello world" "id:402,phase:1,pass,log"

# Test 5: ARGS_GET_NAMES_RAW preserves raw GET argument names
SecRule ARGS_GET_NAMES_RAW "@contains p%61ram" "id:500,phase:1,pass,log"
SecRule ARGS_GET_NAMES "@streq param" "id:501,phase:1,pass,log"
SecRule ARGS_GET_NAMES_RAW "@streq param" "id:502,phase:1,pass,log"

# Test 6: ARGS_POST_NAMES_RAW preserves raw POST argument names
SecRule ARGS_POST_NAMES_RAW "@contains p%61ssword" "id:600,phase:2,pass,log"
SecRule ARGS_POST_NAMES "@streq password" "id:601,phase:2,pass,log"
SecRule ARGS_POST_NAMES_RAW "@streq password" "id:602,phase:2,pass,log"

# Test 7: ARGS_GET_RAW handles multiple values for the same key
SecRule ARGS_GET_RAW:color "@contains gr%65en" "id:700,phase:1,pass,log"
SecRule ARGS_GET:color "@contains green" "id:701,phase:1,pass,log"
SecRule ARGS_GET_RAW:color "@streq green" "id:702,phase:1,pass,log"
`,
})
