// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the rule metadata",
		Enabled:     true,
		Name:        "rulemetadata.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "rulemetadata",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id:1, log, severity:5"
SecRule HIGHEST_SEVERITY "@eq 5" "id:2, log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "majiayu000",
		Description: "Test HIGHEST_SEVERITY defaults to 255 when no rules with severity fire",
		Enabled:     true,
		Name:        "rulemetadata_default_severity.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "highest_severity_default",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRule HIGHEST_SEVERITY "@eq 255" "id:1, log"
`,
})

// Regression: a rule without severity must not poison HIGHEST_SEVERITY.
// Without the RuleSeverityUnset sentinel, the no-severity rule's zero value (0)
// would win over a later explicit severity:5, leaving HIGHEST_SEVERITY stuck at 0.
var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "majiayu000",
		Description: "Test that rules without severity do not poison HIGHEST_SEVERITY",
		Enabled:     true,
		Name:        "rulemetadata_no_severity_poison.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "no_severity_then_explicit",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2, 3},
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id:1, log"
SecAction "id:2, log, severity:5"
SecRule HIGHEST_SEVERITY "@eq 5" "id:3, log"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "majiayu000",
		Description: "Test HIGHEST_SEVERITY with multiple severities keeps the lowest number",
		Enabled:     true,
		Name:        "rulemetadata_highest_severity.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "highest_severity_multiple",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2, 3},
						},
					},
				},
			},
		},
	},
	Rules: `
SecAction "id:1, log, severity:5"
SecAction "id:2, log, severity:2"
SecRule HIGHEST_SEVERITY "@eq 2" "id:3, log"
`,
})
