package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.ProfileMeta{
		Author:      "jptosso",
		Description: "Test if the response action works",
		Enabled:     true,
		Name:        "response.yaml",
	},
	Tests: []profile.ProfileTest{
		{
			Title: "response",
			Stages: []profile.ProfileStage{
				{
					Stage: profile.ProfileSubStage{
						Input: profile.ProfileStageInput{
							URI: "/test.php?id=12345",
						},
						Output: profile.ExpectedOutput{
							Headers: map[string]string{
								"content-type": "secret/mime",
							},
							Data:           `<?php echo "Hello World!\n" ?>`,
							TriggeredRules: []int{953120},
						},
					},
				},
			},
		},
	},
	Rules: `
SecResponseBodyAccess On
SecResponseBodyMimeType secret/mime
SecRule RESPONSE_BODY "@rx <\?(?:=|php)?\s+" \
  "id:953120,\
  phase:4,\
  block,\
  capture,\
  log"
`,
})
