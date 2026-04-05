//go:build coraza.rule.rx_prefilter

// rxprefilter_crs_test.go: correctness and benchmark tests driven entirely by
// the official OWASP CRS.
//
// No proprietary data is used. Both the @rx patterns and the attack payloads
// are read at test time from:
//
//   github.com/corazawaf/coraza-coreruleset         ← rule conf files
//   github.com/corazawaf/coraza-coreruleset/tests   ← official FTW YAML tests
//
// Both packages are already in the module graph (go.mod).
//
// What this file tests / benchmarks
// ----------------------------------
//  TestCRSPrefilterCoverage     – how many CRS @rx rules get a prefilter,
//                                 broken down by attack category.
//  TestCRSPrefilterSafety       – for every attack payload in the official FTW
//                                 tests: if the prefilter rejects the input the
//                                 full regex must also reject it (no false
//                                 negatives).
//  BenchmarkCRSPrefilterVsRegex – per-category median: regex-only vs prefilter.

package operators

import (
	"fmt"
	"io/fs"
	"net/url"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset"
	crstests "github.com/corazawaf/coraza-coreruleset/tests"
)

// ---------------------------------------------------------------------------
// CRS rule parsing
// ---------------------------------------------------------------------------

type crsRule struct {
	id      string
	pattern string
	pl      int // CRS paranoia level (1-4); 0 = unknown
}

// parseCRSRules reads all @rx patterns from the CRS rule files embedded in
// coreruleset.FS. Multi-line SecRule directives (lines ending with \) are
// joined before extraction.
func parseCRSRules() ([]crsRule, error) {
	confFiles, err := fs.Glob(coreruleset.FS, "@owasp_crs/REQUEST-*.conf")
	if err != nil {
		return nil, err
	}

	var rules []crsRule
	seen := map[string]bool{}

	for _, cf := range confFiles {
		data, err := fs.ReadFile(coreruleset.FS, cf)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", cf, err)
		}

		// Join continuation lines.
		joined := joinContinuationLines(string(data))

		for _, line := range strings.Split(joined, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "SecRule") {
				continue
			}
			if !strings.Contains(line, "@rx ") {
				continue
			}

			id := extractSecRuleID(line)
			pattern := extractRXPattern(line)
			if id == "" || pattern == "" || seen[id] {
				continue
			}

			// Validate it's a legal Go regex before adding.
			if _, err := syntax.Parse(pattern, syntax.Perl); err != nil {
				continue
			}
			seen[id] = true
			rules = append(rules, crsRule{id: id, pattern: pattern, pl: extractPL(line)})
		}
	}
	return rules, nil
}

// joinContinuationLines merges lines ending with " \" into the next line.
func joinContinuationLines(src string) string {
	lines := strings.Split(src, "\n")
	var out []string
	var cur strings.Builder
	for _, l := range lines {
		trimmed := strings.TrimRight(l, " \t")
		if strings.HasSuffix(trimmed, "\\") {
			cur.WriteString(strings.TrimSuffix(trimmed, "\\"))
			cur.WriteString(" ")
		} else {
			cur.WriteString(l)
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return strings.Join(out, "\n")
}

// extractSecRuleID pulls the id:NNNN value from a SecRule line.
func extractSecRuleID(line string) string {
	const marker = "id:"
	idx := strings.Index(line, marker)
	if idx < 0 {
		return ""
	}
	s := line[idx+len(marker):]
	// id is followed by comma, space or quote
	end := strings.IndexAny(s, ", \t\"'\\")
	if end < 0 {
		end = len(s)
	}
	return strings.TrimSpace(s[:end])
}

// extractRXPattern pulls the pattern argument from "@rx PATTERN".
func extractRXPattern(line string) string {
	const marker = `"@rx `
	idx := strings.Index(line, marker)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(marker):]
	// Pattern ends at the closing quote of the SecRule action string.
	// The closing quote is the first unescaped " character.
	var sb strings.Builder
	for i := 0; i < len(rest); i++ {
		if rest[i] == '"' {
			break
		}
		if rest[i] == '\\' && i+1 < len(rest) && rest[i+1] == '"' {
			sb.WriteByte('"')
			i++
			continue
		}
		sb.WriteByte(rest[i])
	}
	return sb.String()
}

// extractPL pulls the paranoia-level/N tag value from a (joined) SecRule line.
// Returns 0 if not found.
func extractPL(line string) int {
	const marker = "paranoia-level/"
	idx := strings.Index(line, marker)
	if idx < 0 {
		return 0
	}
	s := line[idx+len(marker):]
	end := strings.IndexAny(s, "', \t\"")
	if end < 0 {
		end = len(s)
	}
	switch strings.TrimSpace(s[:end]) {
	case "1":
		return 1
	case "2":
		return 2
	case "3":
		return 3
	case "4":
		return 4
	}
	return 0
}

// ---------------------------------------------------------------------------
// CRS FTW test YAML parsing
// ---------------------------------------------------------------------------

type ftWPayload struct {
	value      string // raw URI or body data
	shouldFire bool   // true if log_contains expects this rule to fire
	ruleID     string
}

// parseFTWPayloads extracts URI and body payloads from the CRS FTW YAML files.
// It reads crstests.FS directly, using simple line-oriented scanning — no YAML
// library dependency.
func parseFTWPayloads() (map[string][]ftWPayload, error) {
	dirs, err := fs.ReadDir(crstests.FS, ".")
	if err != nil {
		return nil, err
	}

	result := make(map[string][]ftWPayload)

	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		yamlFiles, err := fs.ReadDir(crstests.FS, dir.Name())
		if err != nil {
			continue
		}
		for _, yf := range yamlFiles {
			if !strings.HasSuffix(yf.Name(), ".yaml") {
				continue
			}
			ruleID := strings.TrimSuffix(yf.Name(), ".yaml")
			path := dir.Name() + "/" + yf.Name()
			data, err := fs.ReadFile(crstests.FS, path)
			if err != nil {
				continue
			}
			payloads := extractPayloadsFromYAML(string(data), ruleID)
			result[ruleID] = append(result[ruleID], payloads...)
		}
	}
	return result, nil
}

// extractPayloadsFromYAML parses URI and body data fields from a single YAML
// file using line-level scanning. It associates each payload with whether the
// test stage expects the rule to fire (log_contains) or not.
func extractPayloadsFromYAML(src, ruleID string) []ftWPayload {
	type stage struct {
		uris  []string
		datas []string
		fires bool
	}

	var stages []stage
	var cur *stage
	lines := strings.Split(src, "\n")

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)

		if line == "- stage:" || strings.HasPrefix(line, "- stage:") {
			stages = append(stages, stage{})
			cur = &stages[len(stages)-1]
			continue
		}
		if cur == nil {
			continue
		}

		if strings.HasPrefix(line, "uri:") {
			v := yamlStringValue(line[4:])
			if v != "" {
				cur.uris = append(cur.uris, v)
			}
		} else if strings.HasPrefix(line, "data:") {
			v := yamlStringValue(line[5:])
			if v != "" {
				cur.datas = append(cur.datas, v)
			}
		} else if strings.HasPrefix(line, "log_contains:") && strings.Contains(line, ruleID) {
			cur.fires = true
		}
	}

	var out []ftWPayload
	for _, s := range stages {
		for _, u := range s.uris {
			// Decode percent-encoding so the prefilter sees the actual bytes.
			decoded, err := url.PathUnescape(u)
			if err != nil {
				decoded = u
			}
			out = append(out, ftWPayload{value: decoded, shouldFire: s.fires, ruleID: ruleID})
		}
		for _, d := range s.datas {
			out = append(out, ftWPayload{value: d, shouldFire: s.fires, ruleID: ruleID})
		}
	}
	return out
}

// yamlStringValue strips leading/trailing spaces and quotes from a YAML
// scalar value.
func yamlStringValue(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	} else if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		s = s[1 : len(s)-1]
	}
	return strings.TrimSpace(s)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// benignCRSPayloads are normal HTTP inputs that should not trigger any WAF rule.
// benignCRSPayloads is a realistic sample of normal HTTP traffic as it
// arrives at a WAF — query strings, POST bodies, header values, JSON payloads,
// path segments.  The set is intentionally varied in length and structure so
// that the benchmark mix reflects production traffic where the vast majority
// of requests are benign.
// benignCRSPayloads is a representative sample of normal HTTP traffic — REST,
// JSON, form data, headers, and short values — used in benchmarks.
var benignCRSPayloads = []string{
	"GET /api/v1/users?page=2&limit=20 HTTP/1.1",
	"Host: api.example.com",
	"Content-Type: application/json",
	"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
	`{"user":"alice","action":"login","remember":true}`,
	`{"items":[{"id":7,"qty":3},{"id":12,"qty":1}],"coupon":"SAVE10"}`,
	"username=bob&email=bob%40example.com&role=viewer",
	"search=winter+jacket&category=clothing&size=M&color=navy",
	"/static/js/app.bundle.js?v=3.14.159",
	"id=7",
}

func categoryFromID(id string) string {
	switch {
	case id >= "930000" && id < "931000":
		return "LFI"
	case id >= "931000" && id < "932000":
		return "RFI"
	case id >= "932000" && id < "933000":
		return "RCE"
	case id >= "933000" && id < "934000":
		return "PHP"
	case id >= "941000" && id < "942000":
		return "XSS"
	case id >= "942000" && id < "943000":
		return "SQLi"
	case id >= "943000" && id < "944000":
		return "Session"
	case id >= "944000" && id < "945000":
		return "Java"
	default:
		return "Other"
	}
}

// ---------------------------------------------------------------------------
// TestCRSPrefilterCoverage
// ---------------------------------------------------------------------------

func TestCRSPrefilterCoverage(t *testing.T) {
	rules, err := parseCRSRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("no CRS rules parsed")
	}

	type catStats struct{ total, withPF int }
	cats := map[string]*catStats{}

	for _, rule := range rules {
		cat := categoryFromID(rule.id)
		if cats[cat] == nil {
			cats[cat] = &catStats{}
		}
		cats[cat].total++
		if prefilterFunc(rule.pattern) != nil {
			cats[cat].withPF++
		}
	}

	t.Logf("CRS @rx prefilter coverage:")
	t.Logf("  %-10s %6s %6s %8s", "Category", "Total", "WithPF", "Coverage")
	totalAll, pfAll := 0, 0
	for _, cat := range []string{"SQLi", "XSS", "RCE", "PHP", "LFI", "RFI", "Java", "Session", "Other"} {
		s := cats[cat]
		if s == nil {
			continue
		}
		pct := float64(s.withPF) / float64(s.total) * 100
		t.Logf("  %-10s %6d %6d %7.0f%%", cat, s.total, s.withPF, pct)
		totalAll += s.total
		pfAll += s.withPF
	}
	t.Logf("  %-10s %6d %6d %7.0f%%", "TOTAL", totalAll, pfAll,
		float64(pfAll)/float64(totalAll)*100)
}

// ---------------------------------------------------------------------------
// TestCRSPrefilterSafety
// ---------------------------------------------------------------------------

// TestCRSPrefilterSafety checks that for every official CRS attack payload
// (log_contains tests), the prefilter never falsely rejects an input that
// the full regex would match — i.e. no false negatives.
func TestCRSPrefilterSafety(t *testing.T) {
	rules, err := parseCRSRules()
	if err != nil {
		t.Fatal(err)
	}
	payloadsByRule, err := parseFTWPayloads()
	if err != nil {
		t.Fatal(err)
	}

	violations := 0
	checked := 0

	for _, rule := range rules {
		pf := prefilterFunc(rule.pattern)
		if pf == nil {
			continue // no prefilter — always runs regex, inherently safe
		}
		re, err := regexp.Compile(rule.pattern)
		if err != nil {
			continue
		}

		payloads := payloadsByRule[rule.id]
		for _, p := range payloads {
			if !p.shouldFire {
				continue // benign test — false positives allowed
			}
			checked++
			pfResult := pf(p.value)
			rxResult := re.MatchString(p.value)

			if !pfResult && rxResult {
				// Prefilter said "no match" but regex says "match" — UNSAFE.
				t.Errorf("SAFETY VIOLATION rule %s: prefilter=false regex=true payload=%q",
					rule.id, truncate(p.value, 80))
				violations++
			}
		}
	}

	t.Logf("Safety check: %d attack payloads verified, %d violations", checked, violations)
	if violations == 0 {
		t.Log("✓ zero false negatives")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---------------------------------------------------------------------------
// BenchmarkCRSPrefilterVsRegex
// ---------------------------------------------------------------------------

// BenchmarkCRSPrefilterVsRegex benchmarks regex-only vs prefilter+regex for
// each CRS attack category using a realistic 9:1 benign-to-attack traffic
// mix that reflects production workloads.  The FTW attack payloads are still
// included to stress-test the safety path.
//
//	go test -tags coraza.rule.rx_prefilter -bench BenchmarkCRSPrefilterVsRegex \
//	    -benchmem -benchtime=3s ./internal/operators/
func BenchmarkCRSPrefilterVsRegex(b *testing.B) {
	rules, err := parseCRSRules()
	if err != nil {
		b.Fatal(err)
	}
	payloadsByRule, err := parseFTWPayloads()
	if err != nil {
		b.Fatal(err)
	}

	type catEntry struct {
		rule     crsRule
		re       *regexp.Regexp
		pf       func(string) bool
		payloads []string
	}
	catEntries := map[string][]catEntry{}

	for _, rule := range rules {
		re, err := regexp.Compile(rule.pattern)
		if err != nil {
			continue
		}
		pf := prefilterFunc(rule.pattern)
		passThrough := func(s string) bool { return true }
		if pf == nil {
			pf = passThrough
		}

		// 9:1 benign-to-attack ratio: append 9 copies of benign payloads
		// per 1 copy of attack payloads.  This reflects the traffic mix that
		// a WAF protecting a real application actually sees in production.
		var attacks []string
		for _, p := range payloadsByRule[rule.id] {
			if p.shouldFire {
				attacks = append(attacks, p.value)
			}
		}
		var payloads []string
		payloads = append(payloads, attacks...)
		for rep := 0; rep < 9; rep++ {
			payloads = append(payloads, benignCRSPayloads...)
		}

		cat := categoryFromID(rule.id)
		catEntries[cat] = append(catEntries[cat], catEntry{rule, re, pf, payloads})
	}

	for _, cat := range []string{"SQLi", "XSS", "RCE", "PHP", "LFI"} {
		entries := catEntries[cat]
		if len(entries) == 0 {
			continue
		}

		b.Run("regex_only/"+cat, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, e := range entries {
					for _, p := range e.payloads {
						_ = e.re.MatchString(p)
					}
				}
			}
		})

		b.Run("prefilter/"+cat, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, e := range entries {
					for _, p := range e.payloads {
						if e.pf(p) {
							_ = e.re.MatchString(p)
						}
					}
				}
			}
		})
	}
}

// BenchmarkCRSPrefilterVsRegexPL1 is the same benchmark restricted to
// Paranoia Level 1 rules only — the default deployment level with the
// highest selectivity prefilters and lowest false-positive rate.
//
//	go test -tags coraza.rule.rx_prefilter -bench BenchmarkCRSPrefilterVsRegexPL1 \
//	    -benchmem -benchtime=3s ./internal/operators/
func BenchmarkCRSPrefilterVsRegexPL1(b *testing.B) {
	rules, err := parseCRSRules()
	if err != nil {
		b.Fatal(err)
	}
	payloadsByRule, err := parseFTWPayloads()
	if err != nil {
		b.Fatal(err)
	}

	type catEntry struct {
		rule     crsRule
		re       *regexp.Regexp
		pf       func(string) bool
		payloads []string
	}
	catEntries := map[string][]catEntry{}

	for _, rule := range rules {
		if rule.pl != 1 {
			continue // PL1 only
		}
		re, err := regexp.Compile(rule.pattern)
		if err != nil {
			continue
		}
		pf := prefilterFunc(rule.pattern)
		if pf == nil {
			pf = func(s string) bool { return true }
		}

		var attacks []string
		for _, p := range payloadsByRule[rule.id] {
			if p.shouldFire {
				attacks = append(attacks, p.value)
			}
		}
		var payloads []string
		payloads = append(payloads, attacks...)
		for rep := 0; rep < 9; rep++ {
			payloads = append(payloads, benignCRSPayloads...)
		}

		cat := categoryFromID(rule.id)
		catEntries[cat] = append(catEntries[cat], catEntry{rule, re, pf, payloads})
	}

	for _, cat := range []string{"SQLi", "XSS", "RCE", "PHP", "LFI"} {
		entries := catEntries[cat]
		if len(entries) == 0 {
			continue
		}
		b.Run("regex_only/"+cat, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, e := range entries {
					for _, p := range e.payloads {
						_ = e.re.MatchString(p)
					}
				}
			}
		})
		b.Run("prefilter/"+cat, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, e := range entries {
					for _, p := range e.payloads {
						if e.pf(p) {
							_ = e.re.MatchString(p)
						}
					}
				}
			}
		})
	}
}
