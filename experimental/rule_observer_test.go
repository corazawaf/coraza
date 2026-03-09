package experimental_test

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

func TestRuleObserver(t *testing.T) {
	testCases := map[string]struct {
		directives   string
		withObserver bool
		expectRules  int
	}{
		"no observer configured": {
			directives: `
				SecRule REQUEST_URI "@contains /test" "id:1000,phase:1,deny"
			`,
			withObserver: false,
			expectRules:  0,
		},
		"single rule observed": {
			directives: `
				SecRule REQUEST_URI "@contains /test" "id:1001,phase:1,deny"
			`,
			withObserver: true,
			expectRules:  1,
		},
		"multiple rules observed": {
			directives: `
				SecRule REQUEST_URI "@contains /a" "id:1002,phase:1,deny"
				SecRule REQUEST_URI "@contains /b" "id:1003,phase:2,deny"
			`,
			withObserver: true,
			expectRules:  2,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var observed []types.RuleMetadata

			cfg := coraza.NewWAFConfig().
				WithDirectives(tc.directives)

			if tc.withObserver {
				cfg = experimental.WAFConfigWithRuleObserver(cfg, func(rule types.RuleMetadata) {
					observed = append(observed, rule)
				})
			}

			waf, err := coraza.NewWAF(cfg)
			if err != nil {
				t.Fatalf("unexpected error creating WAF: %v", err)
			}
			if waf == nil {
				t.Fatal("waf is nil")
			}

			if len(observed) != tc.expectRules {
				t.Fatalf("expected %d observed rules, got %d", tc.expectRules, len(observed))
			}

			for _, rule := range observed {
				if rule.ID() == 0 {
					t.Fatal("expected rule ID to be set")
				}
				if rule.File() == "" {
					t.Fatal("expected rule file to be set")
				}
				if rule.Line() == 0 {
					t.Fatal("expected rule line to be set")
				}
			}
		})
	}
}
