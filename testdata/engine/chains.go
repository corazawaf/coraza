package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.ProfileMeta{
		Author:      "jptosso",
		Description: "Test if the chain action works",
		Enabled:     true,
		Name:        "chains.yaml",
	},
	Tests: []profile.ProfileTest{
		{
			Title: "chains",
			Stages: []profile.ProfileStage{
				{
					Stage: profile.ProfileSubStage{
						Input: profile.ProfileStageInput{
							URI: "/test1.php?id=12345",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 1313},
							NonTriggeredRules: []int{2, 200, 20},
						},
					},
				},
				{
					Stage: profile.ProfileSubStage{
						Input: profile.ProfileStageInput{
							URI: "/test2.php?var=prepayloadpost",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 200},
							NonTriggeredRules: []int{2, 1313, 20},
							LogContains:       "found within ARGS:var: prepayloadpost",
						},
					},
				},
				{
					Stage: profile.ProfileSubStage{
						Input: profile.ProfileStageInput{
							URI: "/test3.php",
							Headers: map[string]string{
								"Host": "attack20ing.com",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 20},
							NonTriggeredRules: []int{2, 1313, 21},
							// LogContains: "FoundChain20 attacking.com in REQUEST_HEADERS:host",
						},
					},
				},
				{
					Stage: profile.ProfileSubStage{
						Input: profile.ProfileStageInput{
							URI: "/test4.php",
							Headers: map[string]string{
								"Host": "attack21ing.com",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{
								1,
								// 21
							},
							NonTriggeredRules: []int{20, 2, 1313},
							// LogContains: "FoundSubChain21 REQUEST_HEADERS:Host in MATCHED_VARS_NAMES:REQUEST_HEADERS:Host",
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id: 1, log, chain"
  SecAction "msg:'chain 2',chain"
  SecAction "msg:'chain 3',chain"
  SecAction "msg:'chain 4'"
      
SecAction "id: 2, log, chain"
  SecAction "chain"
  SecAction "chain"
  SecRule ARGS "@noMatch" ""

SecRule REQUEST_URI "@rx (\d\d+)" "id:1313, chain, log"
  SecRule REQUEST_METHOD "GET" ""

SecRule ARGS "@rx prepayloadpost"  "id:200, phase:2, log, msg:'Rule Parent 200', \
  logdata:'Matched Data: %{TX.0} found within %{TX.200_MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
  setvar:'tx.200_matched_var_name=%{MATCHED_VAR_NAME}',\
  chain"
  SecRule MATCHED_VAR "@rx pre" "chain"
    SecRule MATCHED_VAR "@rx post"

SecRule REQUEST_HEADERS "@rx attack20" \
  "id:20,\
  phase:1,\
  log,\
  msg:'Chained rule Parent test',\
  logdata:'FoundChain20 %{MATCHED_VAR} in %{MATCHED_VAR_NAME}',\
  chain"
  SecRule MATCHED_VARS_NAMES "@rx host" \
    "block"

SecRule REQUEST_HEADERS "@rx attack21" \
  "id:21,\
  phase:1,\
  log,\
  chain"
  SecRule MATCHED_VARS_NAMES "@rx (?i:host)" \
    "msg:'Sub Chain Rule',\
    logdata:'FoundSubChain21 %{MATCHED_VAR} in %{MATCHED_VAR_NAME}',\
    chain"
    SecRule MATCHED_VAR_NAME "@rx MATCHED_VARS_NAMES:REQUEST_HEADERS:Host" \
    "msg:'Sub Sub Chain Rule',\
    logdata:'FoundSubSubChain21 %{MATCHED_VAR} in %{MATCHED_VAR_NAME}',\
    block"
`,
})
