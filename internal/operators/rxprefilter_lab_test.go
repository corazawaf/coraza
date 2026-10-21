// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

// rxprefilter_lab_test.go: differential check of the @rx prefilter against a real
// ruleset. It is run by scripts/rx-prefilter-gate.sh (see docs/rx-prefilter-gate.md),
// not by the regular suite: it skips unless CORAZA_PREFILTER_RULES names a directory
// of *.conf files (an unzipped ruleset archive, say). It could not be an engine
// profile or a table row because its input is a ruleset that is not in this
// repository and changes every day.
//
// For every @rx pattern in that ruleset it builds the operator twice, with and
// without the prefilter, feeds both the same inputs and requires the same answer.
// The inputs are generated from the pattern itself (see rxprefilter_gen_test.go),
// so that most of them are strings the regular expression matches: those are
// exactly the inputs a wrong prefilter would reject.

package operators

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// labRxPatterns returns the distinct @rx and !@rx patterns of every SecRule in dir.
func labRxPatterns(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.conf"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no *.conf files in %s (%v)", dir, err)
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(joinLabContinuations(string(data)), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "SecRule ") {
				continue
			}
			// SecRule VARIABLES "OPERATOR ARGUMENTS" "ACTIONS": the operator is the
			// first quoted string.
			start := strings.IndexByte(line, '"')
			if start < 0 {
				continue
			}
			var op strings.Builder
			closed := false
			for i := start + 1; i < len(line); i++ {
				if line[i] == '\\' && i+1 < len(line) && line[i+1] == '"' {
					op.WriteByte('"')
					i++
					continue
				}
				if line[i] == '"' {
					closed = true
					break
				}
				op.WriteByte(line[i])
			}
			if !closed {
				continue
			}
			s := op.String()
			s = strings.TrimPrefix(s, "!")
			pat, ok := strings.CutPrefix(s, "@rx ")
			if !ok || pat == "" || strings.Contains(pat, "%{") || seen[pat] {
				continue
			}
			seen[pat] = true
			out = append(out, pat)
		}
	}
	sort.Strings(out)
	return out
}

func joinLabContinuations(src string) string {
	var out []string
	var cur strings.Builder
	for _, l := range strings.Split(src, "\n") {
		trimmed := strings.TrimRight(l, " \t\r")
		if strings.HasSuffix(trimmed, "\\") {
			cur.WriteString(strings.TrimSuffix(trimmed, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(l)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return strings.Join(out, "\n")
}

func TestRxPrefilterAgainstLabRuleset(t *testing.T) {
	dir := os.Getenv("CORAZA_PREFILTER_RULES")
	if dir == "" {
		t.Skip("CORAZA_PREFILTER_RULES not set")
	}
	patterns := labRxPatterns(t, dir)
	t.Logf("%d distinct @rx patterns in %s", len(patterns), dir)

	samples := 150
	if v := os.Getenv("CORAZA_PREFILTER_SAMPLES"); v != "" {
		if _, err := fmt.Sscan(v, &samples); err != nil {
			t.Fatalf("CORAZA_PREFILTER_SAMPLES=%q: %v", v, err)
		}
	}
	tx := corazawaf.NewWAF().NewTransaction()
	defer tx.Close()

	type failure struct {
		pattern string
		count   int
		first   string
	}
	var failures []failure
	var compiled, withPrefilter, matchedInputs, inputs, violations int
	for _, pat := range patterns {
		if _, err := newRX(plugintypes.OperatorOptions{Arguments: pat, RxPreFilterEnabled: false}); err != nil {
			continue // the ruleset itself would not load this one
		}
		on, err := newRX(plugintypes.OperatorOptions{Arguments: pat, RxPreFilterEnabled: true})
		if err != nil {
			t.Errorf("pattern compiles without the prefilter but not with it: %q: %v", pat, err)
			continue
		}
		compiled++
		if r, ok := on.(*rx); ok && (r.prefilter != nil || r.minLen > 0 || r.exactMatch != "") {
			withPrefilter++
		}

		matched, compared, disagreements, first, err := prefilterDisagreement(pat, samples, tx)
		if err != nil {
			continue
		}
		inputs += compared
		matchedInputs += matched
		violations += disagreements
		if disagreements > 0 {
			failures = append(failures, failure{pat, disagreements, first})
		}
	}
	t.Logf("%d patterns compiled, %d of them with a prefilter, minimum length or exact match", compiled, withPrefilter)
	t.Logf("%d inputs compared, %d of them matched by the regex, %d disagreements in %d patterns", inputs, matchedInputs, violations, len(failures))
	// Every failing pattern, not only the first few: one cause often hides several.
	for _, f := range failures {
		t.Errorf("prefilter changed the answer on %d inputs: pattern %q first input %q", f.count, f.pattern, truncateLab(f.first))
	}
	if matchedInputs == 0 {
		t.Error("no generated input matched any pattern: the generator is not doing its job")
	}
}

func truncateLab(s string) string {
	if len(s) <= 100 {
		return s
	}
	return s[:100] + "..."
}
