// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/seclang"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// wafWithRules mirrors experimental.WAFWithRules for testing without import cycle.
type wafWithRules interface {
	RulesCount() int
}

func TestRequestBodyLimit(t *testing.T) {
	testCases := map[string]struct {
		expectedErr   error
		limit         int
		inMemoryLimit int
	}{
		"empty limit": {
			limit:         0,
			inMemoryLimit: 2,
			expectedErr:   errors.New("request body limit should be bigger than 0"),
		},
		"empty memory limit": {
			limit:         2,
			inMemoryLimit: 0,
			expectedErr:   errors.New("request body memory limit should be bigger than 0"),
		},
		"memory limit bigger than limit": {
			limit:         5,
			inMemoryLimit: 9,
			expectedErr:   errors.New("request body limit should be at least the memory limit"),
		},
		"limit bigger than the hard limit": {
			limit:       1073741825,
			expectedErr: errors.New("request body limit should be at most 1GiB"),
		},
		"right limits": {
			limit:         100,
			inMemoryLimit: 50,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := NewWAFConfig().(*wafConfig)
			cfg.requestBodyLimit = &tCase.limit
			cfg.requestBodyInMemoryLimit = &tCase.inMemoryLimit

			_, err := NewWAF(cfg)
			if tCase.expectedErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %s", err.Error())
				}
			} else {
				if err == nil {
					t.Fatal("expected error")
				}

				if want, have := tCase.expectedErr, err; want.Error() != have.Error() {
					t.Fatalf("unexpected error: want %q, have %q", want, have)
				}
			}
		})
	}
}

func TestResponseBodyLimit(t *testing.T) {
	testCases := map[string]struct {
		expectedErr error
		limit       int
	}{
		"empty limit": {
			limit:       0,
			expectedErr: errors.New("response body limit should be bigger than 0"),
		},
		"limit bigger than the hard limit": {
			limit:       1073741825,
			expectedErr: errors.New("response body limit should be at most 1GiB"),
		},
		"right limit": {
			limit: 100,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := NewWAFConfig().(*wafConfig)
			cfg.responseBodyLimit = &tCase.limit

			_, err := NewWAF(cfg)
			if tCase.expectedErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %s", err.Error())
				}
			} else {
				if err == nil {
					t.Fatal("expected error")
				}

				if want, have := tCase.expectedErr, err; want.Error() != have.Error() {
					t.Fatalf("unexpected error: want %q, have %q", want, have)
				}
			}
		})
	}
}

type testAuditLogWriter struct {
	plugintypes.AuditLogWriter
}

func (*testAuditLogWriter) Init(plugintypes.AuditLogConfig) error {
	return nil
}

func TestPopulateAuditLog(t *testing.T) {
	writer := &testAuditLogWriter{}

	testCases := map[string]struct {
		config *wafConfig
		check  func(*testing.T, *corazawaf.WAF)
	}{
		"empty config": {
			config: &wafConfig{},
			check:  func(*testing.T, *corazawaf.WAF) {},
		},
		"with relevant only": {
			config: &wafConfig{
				auditLog: &auditLogConfig{
					relevantOnly: true,
				},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				if waf.AuditEngine != types.AuditEngineRelevantOnly {
					t.Fatal("expected AuditLogRelevantOnly to be true")
				}
			},
		},
		"with parts": {
			config: &wafConfig{
				auditLog: &auditLogConfig{
					parts: []types.AuditLogPart{
						types.AuditLogPartRequestHeaders,
						types.AuditLogPartResponseBody,
					},
				},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				if want, have := []types.AuditLogPart{
					types.AuditLogPartRequestHeaders,
					types.AuditLogPartResponseBody,
				}, waf.AuditLogParts; len(want) != len(have) {
					t.Fatalf("unexpected AuditLogParts: want %v, have %v", want, have)
				}
			},
		},
		"with audit log writer": {
			config: &wafConfig{
				auditLog: &auditLogConfig{writer: writer},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				if reflect.DeepEqual(waf.AuditLogWriter(), &writer) {
					t.Fatal("expected AuditLogWriter to be set")
				}
			},
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			waf := &corazawaf.WAF{}
			populateAuditLog(waf, tCase.config)
			tCase.check(t, waf)
		})
	}
}

func TestDetectionOnlyEnforcesProcessPartialBodyLimitActions(t *testing.T) {
	waf, err := NewWAF(NewWAFConfig().WithDirectives(`
		SecRuleEngine DetectionOnly
		SecRequestBodyAccess On
		SecRequestBodyLimitAction Reject
		SecResponseBodyAccess On
		SecResponseBodyLimitAction Reject
	`))
	if err != nil {
		t.Fatal(err)
	}

	w := waf.(wafWrapper).waf
	if w.RequestBodyLimitAction != types.BodyLimitActionProcessPartial {
		t.Fatalf("expected RequestBodyLimitAction to be ProcessPartial in DetectionOnly mode, got %v", w.RequestBodyLimitAction)
	}
	if w.ResponseBodyLimitAction != types.BodyLimitActionProcessPartial {
		t.Fatalf("expected ResponseBodyLimitAction to be ProcessPartial in DetectionOnly mode, got %v", w.ResponseBodyLimitAction)
	}
}

func TestRulesCount(t *testing.T) {
	waf, err := NewWAF(NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	rules, ok := waf.(wafWithRules)
	if !ok {
		t.Fatal("WAF does not implement WAFWithRules")
	}
	if rules.RulesCount() != 0 {
		t.Fatalf("expected 0 rules, got %d", rules.RulesCount())
	}

	waf, err = NewWAF(NewWAFConfig().
		WithDirectives(`SecRule REMOTE_ADDR "127.0.0.1" "id:1,phase:1,deny,status:403"`).
		WithDirectives(`SecRule REQUEST_URI "/test" "id:2,phase:1,deny,status:403"`))
	if err != nil {
		t.Fatal(err)
	}

	rules, ok = waf.(wafWithRules)
	if !ok {
		t.Fatal("WAF does not implement WAFWithRules")
	}
	if rules.RulesCount() != 2 {
		t.Fatalf("expected 2 rules, got %d", rules.RulesCount())
	}
}

// Not a profile: engine profiles compile directives into one WAF and cannot pass one *corazawaf.Rule via WithRules into two WAFs.
func TestWithRulesIsolatesGroupsAndCtlSelection(t *testing.T) {
	seedWAF := corazawaf.NewWAF()
	if err := seclang.NewParser(seedWAF).FromString(`
		SecRule ARGS "@streq attack" "id:100,phase:2,deny,status:403,tag:'base'"
		SecRule ARGS:act "@streq hit" "id:101,phase:2,deny,status:403"
		SecRule REQUEST_URI "@beginsWith /chain" "id:200,phase:2,deny,status:403,chain"
		SecRule ARGS:part "@streq evil" ""
		SecRule REQUEST_URI "@beginsWith /handchain" "id:201,phase:1,deny,status:403"
		SecRule &ARGS_POST "@eq 0" "id:202,phase:1,pass"
	`); err != nil {
		t.Fatalf("failed to parse seed rules: %v", err)
	}
	shared := seedWAF.Rules.FindByID(100)
	// Ensure Tags_ has spare capacity so an uncloned append in waf2 would overwrite waf1's tag.
	shared.Tags_ = append(make([]string, 0, 4), shared.Tags_...)
	sharedAction := seedWAF.Rules.FindByID(101)
	sharedChain := seedWAF.Rules.FindByID(200)

	// Hand-built chain whose chainMinPhase is intentionally unset (PhaseUnknown).
	handChain := seedWAF.Rules.FindByID(201)
	handChild := *seedWAF.Rules.FindByID(202)
	handChild.ID_ = 0
	handChild.ParentID_ = 201
	handChild.LogID_ = "201"
	handChild.Phase_ = 0
	handChain.HasChain = true
	handChain.Chain = &handChild

	var observedRule100 types.RuleMetadata
	baseCfg := NewWAFConfig().WithDirectives(`
		SecRuleEngine On
		SecRule ARGS:skip_rule "@streq 1" "id:1,phase:1,pass,nolog,ctl:ruleRemoveByTag=keep-tag"
		SecRule ARGS:skip_target "@streq 1" "id:2,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=keep-tag;ARGS:payload"
	`).(*wafConfig).WithRules(shared, sharedAction, sharedChain, handChain)

	waf1, err := NewWAF(baseCfg.(*wafConfig).WithRuleObserver(func(r types.RuleMetadata) {
		if r.ID() == 100 {
			observedRule100 = r
		}
	}).WithDirectives(`
		SecRuleUpdateActionById 100 "tag:'keep-tag',t:lowercase"
		SecRuleUpdateTargetById 100 "!ARGS:waf1_safe"
	`))
	if err != nil {
		t.Fatalf("NewWAF(waf1) failed: %v", err)
	}

	waf2, err := NewWAF(baseCfg.WithDirectives(`
		SecRuleUpdateActionById 100 "tag:'other-tag'"
		SecRuleUpdateTargetById 100 "!ARGS:waf2_safe"
		SecRuleUpdateActionById 101 "pass"
	`))
	if err != nil {
		t.Fatalf("NewWAF(waf2) failed: %v", err)
	}
	// Mutating waf2's cloned chain child must not leak into waf1 or the seed chain.
	if err := waf2.(wafWrapper).waf.Rules.FindByID(200).Chain.AddVariableNegation(variables.Args, "part"); err != nil {
		t.Fatalf("AddVariableNegation on waf2 chain failed: %v", err)
	}

	evalRequest := func(t *testing.T, w WAF, uri string) *types.Interruption {
		t.Helper()
		tx := w.NewTransaction()
		defer func() {
			if err := tx.Close(); err != nil {
				t.Errorf("tx.Close failed: %v", err)
			}
		}()
		tx.ProcessURI(uri, "GET", "HTTP/1.1")
		if it := tx.ProcessRequestHeaders(); it != nil {
			return it
		}
		it, err := tx.ProcessRequestBody()
		if err != nil {
			t.Errorf("ProcessRequestBody failed: %v", err)
			return nil
		}
		return it
	}

	tests := []struct {
		name            string
		uri             string
		wantWAF1Blocked bool
		wantWAF2Blocked bool
	}{
		{
			name:            "matching payload blocked in both WAFs without exclusions",
			uri:             "/?payload=attack",
			wantWAF1Blocked: true,
			wantWAF2Blocked: true,
		},
		{
			name:            "ctl ruleRemoveByTag selects waf1 tag after spare-capacity tag append in waf2",
			uri:             "/?skip_rule=1&payload=attack",
			wantWAF1Blocked: false,
			wantWAF2Blocked: true,
		},
		{
			name:            "ctl ruleRemoveTargetByTag selects waf1 tag after spare-capacity tag append in waf2",
			uri:             "/?skip_target=1&payload=attack",
			wantWAF1Blocked: false,
			wantWAF2Blocked: true,
		},
		{
			name:            "target negation in waf1 does not leak to waf2",
			uri:             "/?waf1_safe=attack",
			wantWAF1Blocked: false,
			wantWAF2Blocked: true,
		},
		{
			name:            "target negation in waf2 does not leak to waf1",
			uri:             "/?waf2_safe=attack",
			wantWAF1Blocked: true,
			wantWAF2Blocked: false,
		},
		{
			name:            "transformation added in waf1 applies only in waf1",
			uri:             "/?payload=ATTACK",
			wantWAF1Blocked: true,
			wantWAF2Blocked: false,
		},
		{
			name:            "disruptive action update in waf2 does not leak to waf1",
			uri:             "/?act=hit",
			wantWAF1Blocked: true,
			wantWAF2Blocked: false,
		},
		{
			name:            "chained rule child mutation in waf2 does not leak to waf1",
			uri:             "/chain?part=evil",
			wantWAF1Blocked: true,
			wantWAF2Blocked: false,
		},
		{
			name:            "hand-built chain with unset chainMinPhase is not skipped in phase 1",
			uri:             "/handchain",
			wantWAF1Blocked: true,
			wantWAF2Blocked: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wg sync.WaitGroup
			for range 4 {
				wg.Add(2)
				go func() {
					defer wg.Done()
					if got := evalRequest(t, waf1, tt.uri) != nil; got != tt.wantWAF1Blocked {
						t.Errorf("waf1 blocked = %v, want %v", got, tt.wantWAF1Blocked)
					}
				}()
				go func() {
					defer wg.Done()
					if got := evalRequest(t, waf2, tt.uri) != nil; got != tt.wantWAF2Blocked {
						t.Errorf("waf2 blocked = %v, want %v", got, tt.wantWAF2Blocked)
					}
				}()
			}
			wg.Wait()
		})
	}

	t.Run("observer snapshot and group rule tags are isolated in both directions", func(t *testing.T) {
		if observedRule100 == nil {
			t.Fatal("observer did not record rule 100")
		}
		g1Rule := waf1.(wafWrapper).waf.Rules.FindByID(100)
		// Mutate observer snapshot in place -> must not affect group rule or source rule.
		observedRule100.Tags()[0] = "observer-edit"
		if g1Rule.Tags_[0] != "base" || shared.Tags_[0] != "base" {
			t.Errorf("observer tag edit leaked: group=%q source=%q", g1Rule.Tags_[0], shared.Tags_[0])
		}
		// Mutate group rule in place -> must not affect observer snapshot or waf2.
		g1Rule.Tags_[0] = "group-edit"
		if observedRule100.Tags()[0] != "observer-edit" {
			t.Errorf("group tag edit leaked to observer: got %q", observedRule100.Tags()[0])
		}
		if got := waf2.(wafWrapper).waf.Rules.FindByID(100).Tags_[0]; got != "base" {
			t.Errorf("group tag edit leaked to waf2: got %q", got)
		}
	})
}
