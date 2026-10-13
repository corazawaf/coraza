// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

// These benchmarks don't currently compile with TinyGo
//go:build !tinygo

package coreruleset

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/experimental/rulefilter"
	"github.com/corazawaf/coraza/v3/types"
)

// Shapes of the large JSON bodies the lab sends (docker/compose/scenarios/
// perf-cloudways-badday.yaml, entries 10 to 12): one object of eight members whose
// values are all 'a', sized to the byte. They are what DEF-57621 is about.
var largeJSONShapes = []struct {
	name string
	size int
	args int
}{
	{"640KB", 640000, 8},
	{"1MB", 1048041, 8},
	{"4.7MB", 4915200, 8},
}

// syntheticJSON builds the body cclient's synth_body builds for the "json" shape:
// {"k0":"aaa…","k1":"aaa…",…} of exactly size bytes.
func syntheticJSON(size, args int) []byte {
	const open, closing, sep = "{", "}", ","
	member := func(i int, val string) string { return fmt.Sprintf("\"k%d\":\"%s\"", i, val) }
	skel := len(open) + len(closing) + (args-1)*len(sep)
	for i := 0; i < args; i++ {
		skel += len(member(i, ""))
	}
	fill := size - skel
	base, extra := fill/args, fill%args
	var sb strings.Builder
	sb.Grow(size)
	sb.WriteString(open)
	for i := 0; i < args; i++ {
		if i > 0 {
			sb.WriteString(sep)
		}
		n := base
		if i < extra {
			n++
		}
		sb.WriteString(member(i, strings.Repeat("a", n)))
	}
	sb.WriteString(closing)
	return []byte(sb.String())
}

// wafdBaseConfig is what wafd's modsecurity.conf sets that matters for the cost
// of a request body, minus the logging directives.
const wafdBaseConfig = `
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimitAction ProcessPartial
SecArgumentSeparator &
SecCookieFormat 0
`

// largeJSONWAF builds the WAF the benchmark runs. With CORAZA_BENCH_RULES set to a
// directory it loads that directory's *.conf, which is how the lab's ruleset
// (the Imunify360 coraza "full" archive, unzipped) is measured. Without it the
// bundled CRS is used at its default paranoia level.
func largeJSONWAF(b *testing.B) coraza.WAF {
	b.Helper()
	conf := coraza.NewWAFConfig().
		WithDirectives(wafdBaseConfig).
		WithDirectives(fmt.Sprintf("SecTmpDir %s\nSecUploadDir %s", os.TempDir(), os.TempDir()))
	// Extra directives go in before the rules, which is where a setting such as
	// SecRxPreFilter has to be to apply to them. Write a newline as \n.
	if extra := os.Getenv("CORAZA_BENCH_DIRECTIVES"); extra != "" {
		conf = conf.WithDirectives(strings.ReplaceAll(extra, `\n`, "\n"))
	}
	if dir := os.Getenv("CORAZA_BENCH_RULES"); dir != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			b.Fatal(err)
		}
		conf = conf.WithDirectives("Include " + filepath.ToSlash(filepath.Join(abs, "*.conf")))
	} else {
		conf = conf.
			WithRootFS(coreruleset.FS).
			WithDirectives(`
SecResponseBodyMimeType text/plain
SecDefaultAction "phase:3,log,auditlog,pass"
SecDefaultAction "phase:4,log,auditlog,pass"
SecDefaultAction "phase:5,log,auditlog,pass"
`).
			WithDirectives("Include @crs-setup.conf.example").
			WithDirectives("Include @owasp_crs/*.conf")
	}
	waf, err := coraza.NewWAF(conf)
	if err != nil {
		b.Fatal(err)
	}
	return waf
}

// ruleTimer attributes wall time to rules through the rule filter hook, which the
// rule group calls for every rule right before it decides whether to run it. The
// time between two calls is therefore the previous rule's evaluation (rules of
// other phases return at once). Stages that are not rules -- writing the body,
// the body processor -- are booked on negative ids, set with begin.
type ruleTimer struct {
	last  int
	since time.Time
	cost  map[int]time.Duration
	meta  map[int]types.RuleMetadata
}

func newRuleTimer() *ruleTimer {
	return &ruleTimer{cost: map[int]time.Duration{}, meta: map[int]types.RuleMetadata{}}
}

func (t *ruleTimer) ShouldIgnore(m types.RuleMetadata) bool {
	now := time.Now()
	t.cost[t.last] += now.Sub(t.since)
	t.last, t.since = m.ID(), now
	if _, ok := t.meta[m.ID()]; !ok {
		t.meta[m.ID()] = m
	}
	return false
}

func (t *ruleTimer) begin(id int) {
	t.last, t.since = id, time.Now()
}

func (t *ruleTimer) end() {
	t.cost[t.last] += time.Since(t.since)
	t.last = 0
}

const (
	stageHeaders  = -1
	stageBodyRead = -2
	stageBody     = -3 // body processor plus phase setup, up to the first rule of phase 2
	stageResponse = -4
	stageLogging  = -5
)

var stageNames = map[int]string{
	stageHeaders:  "stage: request headers",
	stageBodyRead: "stage: write request body",
	stageBody:     "stage: request body processor (up to first phase-2 rule)",
	stageResponse: "stage: response headers",
	stageLogging:  "stage: logging",
}

func (t *ruleTimer) report(iterations int, top int) string {
	type row struct {
		id int
		d  time.Duration
	}
	var total time.Duration
	rows := make([]row, 0, len(t.cost))
	for id, d := range t.cost {
		if id == 0 {
			continue
		}
		rows = append(rows, row{id, d})
		total += d
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].d > rows[j].d })
	var sb strings.Builder
	fmt.Fprintf(&sb, "per-transaction cost, %d iterations, %.1f ms total per transaction\n", iterations, float64(total)/float64(iterations)/1e6)
	if top > len(rows) {
		top = len(rows)
	}
	for _, r := range rows[:top] {
		name := stageNames[r.id]
		if m, ok := t.meta[r.id]; ok {
			raw := strings.Join(strings.Fields(m.Raw()), " ")
			if len(raw) > 110 {
				raw = raw[:110] + "…"
			}
			name = fmt.Sprintf("rule %d (phase %d, @%s) %s", r.id, m.Phase(), m.Operator(), raw)
		}
		fmt.Fprintf(&sb, "%8.2f ms %5.1f%%  %s\n", float64(r.d)/float64(iterations)/1e6, 100*float64(r.d)/float64(total), name)
	}
	return sb.String()
}

// BenchmarkCRSLargeJSON measures one POST with a large JSON body through the whole
// request/response cycle, per lab body shape. Profile one shape at a time:
//
//	go test -run '^$' -bench 'CRSLargeJSON/4.7MB' -benchmem -cpuprofile cpu.out ./testing/coreruleset/
//
// CORAZA_BENCH_RULES=<dir with *.conf> swaps the bundled CRS for another ruleset,
// CORAZA_BENCH_DIRECTIVES adds directives ahead of the rules (for example
// "SecRxPreFilter On"), CORAZA_BENCH_RULECOST=1 prints the rules that cost the
// most (use -v).
func BenchmarkCRSLargeJSON(b *testing.B) {
	waf := largeJSONWAF(b)
	if closer, ok := waf.(experimental.WAFCloser); ok {
		defer closer.Close()
	}
	ruleCost := os.Getenv("CORAZA_BENCH_RULECOST") == "1"
	reports := map[string]string{}

	for _, shape := range largeJSONShapes {
		body := syntheticJSON(shape.size, shape.args)
		b.Run(shape.name, func(b *testing.B) {
			var timer *ruleTimer
			if ruleCost {
				timer = newRuleTimer()
			}
			stage := func(id int) {
				if timer != nil {
					timer.begin(id)
				}
			}
			endStage := func() {
				if timer != nil {
					timer.end()
				}
			}
			var fired []int
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tx := waf.NewTransaction()
				if timer != nil {
					if err := rulefilter.SetRuleFilter(tx, timer); err != nil {
						b.Fatal(err)
					}
				}
				tx.ProcessConnection("127.0.0.1", 40000, "127.0.0.1", 80)
				tx.ProcessURI("/api/v1/items", "POST", "HTTP/1.1")
				tx.AddRequestHeader("Host", "localhost")
				tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
				tx.AddRequestHeader("Accept", "application/json")
				tx.AddRequestHeader("Content-Type", "application/json")
				tx.AddRequestHeader("Content-Length", fmt.Sprint(len(body)))
				stage(stageHeaders)
				tx.ProcessRequestHeaders()
				endStage()
				stage(stageBodyRead)
				if _, _, err := tx.WriteRequestBody(body); err != nil {
					b.Fatal(err)
				}
				endStage()
				stage(stageBody)
				if _, err := tx.ProcessRequestBody(); err != nil {
					b.Fatal(err)
				}
				endStage()
				tx.AddResponseHeader("Content-Type", "application/json")
				stage(stageResponse)
				tx.ProcessResponseHeaders(200, "OK")
				endStage()
				stage(stageLogging)
				tx.ProcessLogging()
				endStage()
				if i == 0 {
					for _, mr := range tx.MatchedRules() {
						fired = append(fired, mr.Rule().ID())
					}
				}
				if err := tx.Close(); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if timer != nil {
				reports[shape.name] = timer.report(b.N, 25)
			}
			if len(fired) > 0 {
				b.Logf("matched rules in the first transaction: %v", fired)
			}
		})
	}
	for _, shape := range largeJSONShapes {
		if r, ok := reports[shape.name]; ok {
			b.Logf("\n%s (%d bytes, %d members)\n%s", shape.name, shape.size, shape.args, r)
		}
	}
}
