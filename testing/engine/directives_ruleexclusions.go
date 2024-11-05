// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "Test SecRuleUpdateTarget directives",
		Enabled:     true,
		Name:        "SecRuleUpdateTarget.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "SecRuleUpdateTarget",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php?t1=aaa&t2=bbb",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/x-www-form-urlencoded",
								"Cookie":       "cookie=aaa",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								20,
								30,
								50,
								62,
								51,
							},
							NonTriggeredRules: []int{
								10,
								12,
								16,
								40,
								60,
								61,
							},
						},
					},
				},
			},
		},
	},
	Rules: `
	# ARGS:t1 is removed by SecRuleUpdateTargetById, rule 10 should not be triggered
	SecRule ARGS:t1 "@rx aaa" "id:10,phase:1,log"
	SecRuleUpdateTargetById 10 "!ARGS:t1"

	# ARGS:t2 is removed by SecRuleUpdateTargetById, rule 12 (in range ids 11-13) should not be triggered
	SecRule ARGS:t2 "@rx bbb" "id:12,phase:1,log"
	SecRuleUpdateTargetById 11-13 "!ARGS:t2"

	# ARGS:t2 is removed by SecRuleUpdateTargetById, rule 16 (in range) should not be triggered
	SecRule ARGS:t2 "@rx bbb" "id:16,phase:1,log"
	SecRuleUpdateTargetById 13-15 16 18 "!ARGS:t2"
	
	# ARGS:t1 is removed by SecRuleUpdateTargetById, but REQUEST_COOKIES should still trigger rule 20
	SecRule ARGS:t1|REQUEST_COOKIES "@rx aaa" "id:20,phase:1,log"
	SecRuleUpdateTargetById 20 "!ARGS:t1"

	# ARGS:t1 is added by SecRuleUpdateTargetById, it should trigger rule 30
	SecRule REQUEST_BODY "@rx aaa" "id:30,phase:1,log"
	SecRuleUpdateTargetById 30 "ARGS:t1"

	# ARGS:t19999 is added by SecRuleUpdateTargetById, it should not trigger rule 40
	SecRule REQUEST_BODY "@rx aaa" "id:40,phase:1,log"
	SecRuleUpdateTargetById 40 "ARGS:t19999"

	# ARGS:t1 is NOT removed by SecRuleUpdateTargetByTag, rule 50 should be triggered
	SecRule ARGS:t1 "@rx aaa" "id:50,phase:1,log,tag:tag-1"
	SecRuleUpdateTargetByTag tag-1111 "!ARGS:t1"

	# ARGS:t1 is NOT removed by SecRuleUpdateTargetByTag. Because case sensitive matching, rule 51 should be triggered
	SecRule ARGS:t1 "@rx aaa" "id:51,phase:1,log,tag:tag-1b"
	SecRuleUpdateTargetByTag tAg-1b "!ARGS:t1"

	# ARGS:t1 is removed by SecRuleUpdateTargetByTag, rule 60,61 should not be triggered.
	SecRule ARGS "@rx aaa" "id:60,phase:1,log,tag:tag-2"
	SecRule ARGS:t2 "@rx bbb" "id:61,phase:1,log,tag:tag-2"
	SecRule ARGS:t1|REQUEST_COOKIES "@rx aaa" "id:62,phase:1,log,tag:tag-2"
	# The tag might also be wrapped in double quotes
	SecRuleUpdateTargetByTag "tag-2" "!ARGS:t1|!ARGS:t2"

	`,
})
