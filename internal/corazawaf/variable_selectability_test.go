// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"testing"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// TestCanBeSelectedMatchesKeyedCollection pins the invariant behind the
// `// CanBeSelected` marker in internal/variables/variables.go: a variable is
// selectable exactly when the collection it resolves to can look a key up.
//
// Both directions fail silently, which is why they need a test:
//   - Keyed but not marked: `SecRule VAR:key` is rejected at parse time and
//     takes the whole rule file down with it.
//   - Marked but not Keyed: the rule compiles and then matches nothing, leaving
//     only a debug log line behind.
//
// The marker is a comment consumed by internal/variables/generator, so nothing
// else - not the compiler, not go vet - checks that a newly added variable
// declares itself correctly.
func TestCanBeSelectedMatchesKeyedCollection(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	t.Cleanup(func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	})

	checked := 0
	// RuleVariable is a byte; the bound keeps a broken sentinel from looping forever.
	for i := 1; i < 256; i++ {
		v := variables.RuleVariable(i)
		if v.Name() == "INVALID_VARIABLE" {
			break
		}
		checked++
		if v == variables.JSON {
			// Marked selectable upstream, but Collection() returns nil for it
			// (see the TODO there), so it cannot satisfy the invariant.
			continue
		}
		if _, keyed := tx.Collection(v).(collection.Keyed); keyed != v.CanBeSelected() {
			t.Errorf("%s: CanBeSelected()=%t, collection implements collection.Keyed=%t",
				v.Name(), v.CanBeSelected(), keyed)
		}
	}

	// Guards against a vacuous pass if Name() ever stops terminating the walk
	// where the enum ends.
	if want := int(variables.ArgumentsLimitReached); checked != want {
		t.Errorf("walked %d variables, expected the whole enum through ARGUMENTS_LIMIT_REACHED (%d)", checked, want)
	}
}

// TestRuleVisibleCollectionsAreReset pins the invariant behind
// TransactionVariables.All: every collection a rule can reach through
// Collection() has to be enumerated there, because reset() walks All() and
// transactions are recycled through a pool.
//
// A collection reachable by a rule but missing from All() keeps its value for
// whichever request gets that transaction next. For an error flag that means a
// clean request inherits the previous one's failure and is denied by a rule it
// never tripped, which is why this is worth a structural test rather than a
// per-variable one: the mistake is invisible at the call site and shows up
// only under pool reuse.
//
// The persistent collections are the deliberate exception - reset() clears
// them explicitly, and the comment there explains why they stay out of All().
func TestRuleVisibleCollectionsAreReset(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	t.Cleanup(func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	})

	enumerated := make(map[collection.Collection]struct{})
	tx.variables.All(func(_ variables.RuleVariable, col collection.Collection) bool {
		enumerated[col] = struct{}{}
		return true
	})

	persistent := map[variables.RuleVariable]struct{}{
		variables.Global:   {},
		variables.Resource: {},
		variables.IP:       {},
		variables.Session:  {},
		variables.User:     {},
	}

	// RuleVariable is a byte; the bound keeps a broken sentinel from looping forever.
	for i := 1; i < 256; i++ {
		v := variables.RuleVariable(i)
		if v.Name() == "INVALID_VARIABLE" {
			break
		}
		if _, skip := persistent[v]; skip {
			continue
		}
		col := tx.Collection(v)
		// Noop is the fallback for variables no collection backs; nil is JSON,
		// which Collection() leaves unimplemented.
		if col == nil || col == collections.Noop {
			continue
		}
		if _, ok := enumerated[col]; !ok {
			t.Errorf("%s is reachable through Collection() but absent from All(), so it survives Close() and leaks into the next transaction", v.Name())
		}
	}
}
