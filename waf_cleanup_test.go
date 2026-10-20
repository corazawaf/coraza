// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.no_memoize

package coraza

import (
	"fmt"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/operators"
)

type cleanupTestOperator struct{}

func (cleanupTestOperator) Evaluate(plugintypes.TransactionState, string) bool { return true }

// Not a profile: it asserts memoize ownership after NewWAF fails, which only exists with memoize built in.
func TestFailedConstructionReleasesCachedResources(t *testing.T) {
	for _, failure := range []string{"parse", "limits"} {
		for _, liveOwner := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/live-owner=%t", failure, liveOwner), func(t *testing.T) {
				compilations := 0
				operators.Register("cleanup-test", func(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
					_, err := options.Memoizer.Do(t.Name(), func() (any, error) {
						compilations++
						return struct{}{}, nil
					})
					return cleanupTestOperator{}, err
				})
				config := NewWAFConfig().WithDirectives(`SecRule ARGS "@cleanup-test" "id:1,phase:1,deny"`)
				var live WAF
				if liveOwner {
					var err error
					live, err = NewWAF(config)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = live.(wafWrapper).Close() })
				}
				invalid := config
				if failure == "parse" {
					invalid = invalid.WithDirectives("NotARealDirective yes")
				} else {
					invalid = invalid.WithRequestBodyLimit(0)
				}
				if waf, err := NewWAF(invalid); err == nil || waf != nil {
					t.Fatalf("expected failed construction, got %v, %v", waf, err)
				}
				if liveOwner {
					other, err := NewWAF(config)
					if err != nil {
						t.Fatal(err)
					}
					_ = other.(wafWrapper).Close()
					if compilations != 1 {
						t.Fatalf("released a live owner's cache: compiled %d times", compilations)
					}
					_ = live.(wafWrapper).Close()
				}
				next, err := NewWAF(config)
				if err != nil {
					t.Fatal(err)
				}
				_ = next.(wafWrapper).Close()
				if compilations != 2 {
					t.Fatalf("failed construction retained cache ownership: compiled %d times", compilations)
				}
			})
		}
	}
}
