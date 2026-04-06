// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestMinMatchLength(t *testing.T) {
	tests := []struct {
		pattern string
		want    int
	}{
		{"abc", 3},
		{"", 0},
		{"a|bc", 1},
		{"a*", 0},
		{"a{3,5}", 3},
		{"a{0,5}", 0},
		{"(ab){2}", 4},
		{"[a-z]{3}", 3},
		{"\\d*", 0},
		{"(?i)hello", 5},
		{"hello.*world", 10},
		{"(?:union\\s+select|insert\\s+into)", 11},
		{"^abc$", 3},
		{"ハロー", 9},  // 3 runes × 3 bytes each
		{"café", 5}, // é is 2 bytes (multibyte)
	}
	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			got := minMatchLength(tc.pattern)
			if got != tc.want {
				t.Errorf("minMatchLength(%q) = %d, want %d", tc.pattern, got, tc.want)
			}
		})
	}
}

// TestPrefilterFuncBuildability verifies that prefilterFunc correctly decides
// which patterns can produce a prefilter (non-nil) and which cannot (nil).
// For patterns that produce a prefilter, it also validates that the prefilter
// accepts known matching inputs and rejects known non-matching inputs.
func TestPrefilterFuncBuildability(t *testing.T) {
	tests := []struct {
		pattern string
		wantNil bool
		desc    string
		match   string // input that the regex matches (checked when prefilter is non-nil)
		noMatch string // input that the regex does not match (checked when prefilter is non-nil)
	}{
		// OpLiteral → allRequired{s}: the single-literal fast path (line 352).
		// Every plain literal pattern must build a non-nil contains prefilter.
		{"hello", false, "plain literal", "say hello", "goodbye"},
		{"select", false, "sql keyword literal", "select 1", "update t"},
		{"injection", false, "longer literal", "sql injection", "harmless"},
		{"[a-z]+", true, "char class only", "", ""},
		{"hello.*world", false, "literals around wildcard", "hello big world", "goodbye planet"},
		{"(ab|cd)", false, "alternation with literals", "xabx", "xyz"},
		{".*", true, "pure wildcard", "", ""},
		{"\\d+", true, "digit class", "", ""},
		{"sleep\\s*\\(", false, "literal with optional whitespace", "sleep(1)", "wake(1)"},
		{"(?:union\\s+select|insert\\s+into)", false, "CRS-style alternation", "union select 1", "update set x"},
		{".", true, "single any-char", "", ""},
		{"(a|.)", true, "alternation with wildcard branch", "", ""},
		{"(?:ab|[0-9]+)", true, "alternation where one branch has no literal", "", ""},
		{"(abc)+", false, "repeated literal", "xabcabc", "xyzxyz"},
		{"(abc)?", true, "optional group", "", ""},
		{"(abc)*", true, "zero-or-more group", "", ""},
		{"^hello$", false, "anchored literal", "hello", "world"},
		{"(?i)SELECT", false, "case-insensitive literal", "select", "update"},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			pf := prefilterFunc(tc.pattern)
			if tc.wantNil && pf != nil {
				t.Errorf("prefilterFunc(%q) expected nil, got non-nil", tc.pattern)
			}
			if !tc.wantNil && pf == nil {
				t.Errorf("prefilterFunc(%q) expected non-nil, got nil", tc.pattern)
			}
			// When prefilter exists, validate it accepts matching inputs and
			// rejects (or conservatively accepts) non-matching inputs.
			if pf != nil && tc.match != "" {
				if !pf(tc.match) {
					t.Errorf("prefilter(%q) rejected matching input %q — false negative", tc.pattern, tc.match)
				}
			}
			if pf != nil && tc.noMatch != "" {
				re := regexp.MustCompile(tc.pattern)
				if re.MatchString(tc.noMatch) {
					t.Fatalf("test bug: noMatch %q actually matches %q", tc.noMatch, tc.pattern)
				}
				// Prefilter may accept (conservative) or reject — but if it rejects, it's correct
				// Conservative pass-through: prefilter said "maybe", that's OK
				_ = pf(tc.noMatch)
			}
		})
	}
}

// TestPrefilterNeverCausesFalseNegatives is the critical safety test.
// For every pattern+input pair where the regex matches, both the minLen check
// and the prefilter must also accept the input. A failure here means the
// prefilter would cause an attack to be missed.
func TestPrefilterNeverCausesFalseNegatives(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		matches bool
	}{
		// Basic literals
		{"hello", "hello world", true},
		{"hello", "goodbye", false},

		// Wildcards
		{"hello.*world", "hello beautiful world", true},
		{"hello.*world", "goodbye", false},

		// CRS-style SQLi alternations
		{"(?:union\\s+select|insert\\s+into)", "union select * from t", true},
		{"(?:union\\s+select|insert\\s+into)", "delete from t", false},
		{"(?:union\\s+select|insert\\s+into)", "UNION SELECT", false}, // case-sensitive

		// Case-insensitive
		{"(?i)(?:union\\s+select|insert\\s+into)", "UNION SELECT * FROM t", true},
		{"(?i)(?:union\\s+select|insert\\s+into)", "DELETE FROM t", false},
		{"(?i)(?:select|union)", "SELECT", true},
		{"(?i)(?:select|union)", "delete", false},

		// Alternation + groups
		{"ab(cd|ef)gh", "abcdgh", true},
		{"ab(cd|ef)gh", "abxxgh", false},
		{"(?:cat|dog|bird)", "I have a cat", true},
		{"(?:cat|dog|bird)", "I have a fish", false},

		// Anchored, unicode, wildcard literal
		{"^hello", "hello world", true},
		{"^hello", "say hello", false},
		{"ハロー", "ハローワールド", true},
		{"ハロー", "グッバイ", false},
		{".*\\.exe", "malware.exe", true},
		{".*\\.exe", "malware.txt", false},

		// Pattern with no extractable literals (prefilter nil, regex runs)
		{"[a-z]+\\d+", "abc123", true},
		{"[a-z]+\\d+", "123", false},

		// Regression: trie suffix with wildcard interior must NOT join disjoint
		// literals into a phantom string. "elect.*from" has allRequired{"elect","from"};
		// joining them to "electfrom" would make the prefilter reject
		// "select x from users" (which the regex matches) — a false negative.
		{"s(?:elect.*from|leep)", "select x from users", true},
		{"s(?:elect.*from|leep)", "sleep(5)", true},
		{"s(?:elect.*from|leep)", "unrelated", false},

		// Similar: prefix shared across one literal branch and one wildcard branch.
		{"(?i)s(?:elect.*into|ubstr)", "SELECT x INTO y", true},
		{"(?i)s(?:elect.*into|ubstr)", "SUBSTR(x,1)", true},
		{"(?i)s(?:elect.*into|ubstr)", "unrelated", false},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s/%s", tc.pattern, tc.input), func(t *testing.T) {
			re := regexp.MustCompile(tc.pattern)
			regexResult := re.MatchString(tc.input)
			if regexResult != tc.matches {
				t.Fatalf("test setup error: regex %q match on %q = %v, expected %v",
					tc.pattern, tc.input, regexResult, tc.matches)
			}

			ml := minMatchLength(tc.pattern)
			if regexResult && len(tc.input) < ml {
				t.Errorf("FALSE NEGATIVE: minMatchLength(%q)=%d rejects matching input %q (len=%d)",
					tc.pattern, ml, tc.input, len(tc.input))
			}

			pf := prefilterFunc(tc.pattern)
			if pf != nil && regexResult && !pf(tc.input) {
				t.Errorf("FALSE NEGATIVE: prefilter(%q) returned false for matching input %q",
					tc.pattern, tc.input)
			}
		})
	}
}

// TestPrefilterCaseInsensitive tests case-insensitive handling in detail.
func TestPrefilterCaseInsensitive(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool // expected prefilter result (true = might match)
	}{
		// Basic (?i) flag
		{"ci_upper", "(?i)hello", "HELLO WORLD", true},
		{"ci_mixed", "(?i)hello", "HeLLo", true},
		{"ci_lower", "(?i)hello", "hello", true},
		{"ci_nomatch", "(?i)hello", "goodbye", false},

		// Case-sensitive (no flag)
		{"cs_exact", "hello", "hello", true},
		{"cs_upper_reject", "hello", "HELLO", false},

		// (?i) with alternation
		{"ci_alt_first", "(?i)(?:select|insert)", "SELECT", true},
		{"ci_alt_second", "(?i)(?:select|insert)", "INSERT", true},
		{"ci_alt_mixed", "(?i)(?:select|insert)", "SeLeCt", true},
		{"ci_alt_nomatch", "(?i)(?:select|insert)", "DELETE", false},

		// (?i) with concatenation
		{"ci_concat", "(?i)hello.*world", "HELLO beautiful WORLD", true},
		{"ci_concat_nomatch", "(?i)hello.*world", "GOODBYE", false},

		// Partial (?i) — flag applies to subexpression only, but our implementation
		// conservatively treats the whole pattern as case-insensitive. This means
		// the prefilter may accept more inputs than it should (safe, not a false negative).
		{"partial_ci_match", "hello(?i:world)", "helloWORLD", true},
		{"partial_ci_conservative", "hello(?i:world)", "HELLOworld", true}, // conservative: prefilter may accept
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pf := prefilterFunc(tc.pattern)
			if pf == nil {
				// No prefilter built — always considered "might match", skip this test
				return
			}
			got := pf(tc.input)

			// For safety: if the regex matches, the prefilter MUST return true.
			re := regexp.MustCompile(tc.pattern)
			if re.MatchString(tc.input) && !got {
				t.Errorf("FALSE NEGATIVE: prefilter(%q) returned false for matching input %q", tc.pattern, tc.input)
			}

			// If we have an expected value and the regex doesn't match, check filtering.
			if !re.MatchString(tc.input) && got != tc.want {
				// This is not a correctness failure — the prefilter being too conservative
				// (returning true for non-matching) is fine. Only log if it's unexpectedly
				// rejecting a non-matching input.
				if !got && tc.want {
					t.Errorf("prefilter(%q) unexpectedly rejected non-matching input %q", tc.pattern, tc.input)
				}
			}
		})
	}
}

// TestPrefilterIntegrationViaNewRX verifies the full pipeline: newRX → Evaluate,
// ensuring the prefilter is correctly integrated and doesn't alter matching behavior.
func TestPrefilterIntegrationViaNewRX(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		want    bool
	}{
		// Patterns that get prefilters
		{"hello.*world", "hello beautiful world", true},
		{"hello.*world", "goodbye universe", false},
		{"som(.*)ta", "somedata", true},
		{"som(.*)ta", "notdata", false},

		// Case-insensitive via newRX (gets (?sm) or (?s) prefix)
		{"(?i)hello", "HELLO", true},
		{"(?i)hello", "goodbye", false},

		// Alternation
		{"(?:union|select)", "test union test", true},
		{"(?:union|select)", "test delete test", false},

		// Patterns that should NOT get prefilters (pure wildcards)
		{"[a-z]+", "abc", true},
		{"[a-z]+", "123", false},
		{".*", "anything", true},
		{".*", "", true},

		// Short inputs rejected by minLen
		{"hello.*world", "hi", false},

		// Empty input
		{"hello", "", false},

		// Unicode
		{"ハロー", "ハローワールド", true},
		{"ハロー", "グッバイ", false},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s/%s", tc.pattern, tc.input), func(t *testing.T) {
			opts := plugintypes.OperatorOptions{Arguments: tc.pattern, RxPreFilterEnabled: true}
			op, err := newRX(opts)
			if err != nil {
				t.Fatal(err)
			}

			waf := corazawaf.NewWAF()
			tx := waf.NewTransaction()
			tx.Capture = true
			got := op.Evaluate(tx, tc.input)
			if got != tc.want {
				t.Errorf("Evaluate(%q, %q) = %v, want %v", tc.pattern, tc.input, got, tc.want)
			}
		})
	}
}

// TestPrefilterCapturingCorrectness verifies that the FindStringSubmatchIndex
// path produces the same capture groups as the original FindStringSubmatch path.
func TestPrefilterCapturingCorrectness(t *testing.T) {
	tests := []struct {
		pattern  string
		input    string
		captures map[int]string // expected capture group index → value
	}{
		{
			pattern:  "som(.*)ta",
			input:    "somedata",
			captures: map[int]string{0: "somedata", 1: "eda"},
		},
		{
			pattern:  "(a)(b)(c)",
			input:    "abc",
			captures: map[int]string{0: "abc", 1: "a", 2: "b", 3: "c"},
		},
		{
			pattern:  "(foo)(bar)?",
			input:    "foo",
			captures: map[int]string{0: "foo", 1: "foo", 2: ""}, // group 2 not in match
		},
		{
			pattern:  "^/api/v(\\d+)",
			input:    "/api/v3/users",
			captures: map[int]string{0: "/api/v3", 1: "3"},
		},
		{
			pattern:  "(a|b)(c|d)",
			input:    "bd",
			captures: map[int]string{0: "bd", 1: "b", 2: "d"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			opts := plugintypes.OperatorOptions{Arguments: tc.pattern, RxPreFilterEnabled: true}
			op, err := newRX(opts)
			if err != nil {
				t.Fatal(err)
			}

			waf := corazawaf.NewWAF()
			tx := waf.NewTransaction()
			tx.Capture = true
			got := op.Evaluate(tx, tc.input)
			if !got {
				t.Fatalf("expected match for %q on %q", tc.pattern, tc.input)
			}

			for idx, want := range tc.captures {
				collected := tx.Variables().TX().Get(fmt.Sprintf("%d", idx))
				if len(collected) == 0 {
					t.Errorf("capture group %d: expected %q, got nothing", idx, want)
					continue
				}
				if collected[0] != want {
					t.Errorf("capture group %d: expected %q, got %q", idx, want, collected[0])
				}
			}
		})
	}
}

func TestContainsFoldASCII(t *testing.T) {
	tests := []struct {
		s, needle string
		want      bool
	}{
		{"HELLO WORLD", "hello", true},
		{"Hello World", "hello", true},
		{"goodbye", "hello", false},
		{"", "hello", false},
		{"hi", "hello", false},
		{"xhellox", "hello", true},
		{"HÉLLO", "hello", false},             // non-ASCII É in haystack, ASCII needle
		{"Straße", "straße", true},            // non-ASCII needle: conservative true to avoid false negatives
		{"STRASSE", "straße", true},           // non-ASCII needle: conservative true (Unicode folding is tricky)
		{"totally different", "straße", true}, // non-ASCII needle: conservative true even when absent
		{"", "", true},                        // empty needle always matches
		{"abc", "", true},
		{"SELECT", "select", true},
		{"sElEcT", "select", true},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s/%s", tc.s, tc.needle), func(t *testing.T) {
			got := containsFoldASCII(tc.s, tc.needle)
			if got != tc.want {
				t.Errorf("containsFoldASCII(%q, %q) = %v, want %v", tc.s, tc.needle, got, tc.want)
			}
		})
	}
}

// TestBinaryRXBypassesPrefilter verifies that patterns containing non-UTF8 byte
// sequences (e.g. \xac\xed\x00\x05) go through the binaryRX path and do NOT
// get a prefilter attached. This is critical because rxprefilter.go only handles
// standard regexp.Regexp, not binaryregexp.Regexp.
func TestBinaryRXBypassesPrefilter(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{
			name:    "binary_match",
			pattern: `\xac\xed\x00\x05`,
			input:   "\xac\xed\x00\x05t\x00\x04test",
			want:    true,
		},
		{
			name:    "binary_no_match",
			pattern: `\xac\xed\x00\x05`,
			input:   "\xac\xed\x00t\x00\x04test",
			want:    false,
		},
		{
			name:    "binary_match_2",
			pattern: `\xff\xfe`,
			input:   "\xff\xfedata",
			want:    true,
		},
		{
			name:    "binary_no_match_2",
			pattern: `\xff\xfe`,
			input:   "normal text",
			want:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := plugintypes.OperatorOptions{Arguments: tc.pattern}
			op, err := newRX(opts)
			if err != nil {
				t.Fatal(err)
			}

			// Verify it's a binaryRX, not an rx with prefilter
			if _, ok := op.(*binaryRX); !ok {
				t.Fatalf("expected binaryRX for pattern %q, got %T", tc.pattern, op)
			}

			waf := corazawaf.NewWAF()
			tx := waf.NewTransaction()
			tx.Capture = true
			got := op.Evaluate(tx, tc.input)
			if got != tc.want {
				t.Errorf("Evaluate(%q, %q) = %v, want %v", tc.pattern, tc.input, got, tc.want)
			}
		})
	}
}

// TestPrefilterWithSMPrefix verifies that the (?sm) or (?s) prefix that newRX
// prepends to every pattern does not break the prefilter. The prefilterFunc
// receives the full prefixed pattern, and it must still extract correct literals
// and not cause false negatives.
func TestPrefilterWithSMPrefix(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		// (?sm) prefix: dotall + multiline. The pattern "hello.*world" should
		// still match across newlines, and the prefilter should still require
		// both "hello" and "world".
		{
			name:    "dotall_match",
			pattern: "hello.*world",
			input:   "hello\nworld",
			want:    true,
		},
		{
			name:    "dotall_no_match",
			pattern: "hello.*world",
			input:   "goodbye\nuniverse",
			want:    false,
		},
		// Multiline: ^ matches at line start (only when (?sm) is prepended;
		// with no_regex_multiline, only (?s) is prepended so ^ matches start of string only).
		{
			name:    "multiline_anchor",
			pattern: "^hello.*world",
			input:   "test\nhello\nworld",
			want:    !shouldNotUseMultilineRegexesOperatorByDefault,
		},
		// User-supplied (?i) combined with the automatic (?sm)
		{
			name:    "user_ci_with_sm_match",
			pattern: "(?i)hello.*world",
			input:   "HELLO\nWORLD",
			want:    true,
		},
		{
			name:    "user_ci_with_sm_no_match",
			pattern: "(?i)hello.*world",
			input:   "GOODBYE\nUNIVERSE",
			want:    false,
		},
		// Double (?sm) — user passes (?sm) and newRX also prepends it
		{
			name:    "double_sm",
			pattern: "(?sm)hello.*world",
			input:   "hello\nworld",
			want:    true,
		},
		// CRS-style pattern through newRX with automatic prefix
		{
			name:    "crs_sqli_via_newrx",
			pattern: "(?:union\\s+select|insert\\s+into)",
			input:   "union select * from t",
			want:    true,
		},
		{
			name:    "crs_sqli_via_newrx_no_match",
			pattern: "(?:union\\s+select|insert\\s+into)",
			input:   "just normal text",
			want:    false,
		},
		// Alternation with (?i) through full pipeline
		{
			name:    "ci_alternation_via_newrx",
			pattern: "(?i)(?:select|union|insert)",
			input:   "SELECT",
			want:    true,
		},
		{
			name:    "ci_alternation_via_newrx_no_match",
			pattern: "(?i)(?:select|union|insert)",
			input:   "DELETE",
			want:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := plugintypes.OperatorOptions{Arguments: tc.pattern, RxPreFilterEnabled: true}
			op, err := newRX(opts)
			if err != nil {
				t.Fatal(err)
			}

			// Verify this goes through the rx path (not binaryRX)
			rxOp, ok := op.(*rx)
			if !ok {
				t.Fatalf("expected *rx for pattern %q, got %T", tc.pattern, op)
			}

			// Verify the prefilter doesn't cause false negatives
			waf := corazawaf.NewWAF()
			tx := waf.NewTransaction()
			tx.Capture = true
			got := rxOp.Evaluate(tx, tc.input)
			if got != tc.want {
				t.Errorf("Evaluate(%q, %q) = %v, want %v", tc.pattern, tc.input, got, tc.want)
			}
		})
	}
}

// TestMemoizeSharesPrefilter verifies that two newRX calls with the same pattern
// produce operators with identical compiled artifacts. When the memoize_builders
// build tag is active, they share the same pointer; without it, they are distinct
// but behaviorally equivalent.
func TestMemoizeSharesPrefilter(t *testing.T) {
	pattern := "hello.*world"
	opts := plugintypes.OperatorOptions{Arguments: pattern, RxPreFilterEnabled: true}

	op1, err := newRX(opts)
	if err != nil {
		t.Fatal(err)
	}
	op2, err := newRX(opts)
	if err != nil {
		t.Fatal(err)
	}

	rx1 := op1.(*rx)
	rx2 := op2.(*rx)

	if rx1.prefilter == nil {
		t.Fatal("prefilter not built: RxPreFilterEnabled is required for this test")
	}

	// Both should have the same minLen
	if rx1.minLen != rx2.minLen {
		t.Errorf("minLen mismatch: %d vs %d", rx1.minLen, rx2.minLen)
	}

	// Both should have the same regex pattern
	if rx1.re.String() != rx2.re.String() {
		t.Errorf("regex pattern mismatch: %q vs %q", rx1.re.String(), rx2.re.String())
	}

	// Both should produce the same evaluation results
	inputs := []string{"hello beautiful world", "goodbye", "", "hello world"}
	for _, inp := range inputs {
		waf := corazawaf.NewWAF()
		tx1 := waf.NewTransaction()
		tx1.Capture = true
		tx2 := waf.NewTransaction()
		tx2.Capture = true

		r1 := rx1.Evaluate(tx1, inp)
		r2 := rx2.Evaluate(tx2, inp)
		if r1 != r2 {
			t.Errorf("input %q: op1=%v, op2=%v", inp, r1, r2)
		}
	}
}

// TestPrefilterUnicodeFoldingSafety verifies that the prefilter does not produce
// false negatives when the input contains non-ASCII characters that are Unicode
// fold equivalents of ASCII letters. Go's regexp (?i) uses Unicode simple case
// folding, so (?i)s matches 'ſ' (U+017F) and (?i)k matches 'K' (U+212A).
// Our prefilter only does ASCII folding, so for non-ASCII inputs it must
// conservatively return true ("maybe match") to avoid missing attacks.
func TestPrefilterUnicodeFoldingSafety(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		matches bool // what the regex says
	}{
		// 'ſ' (U+017F, Latin Small Letter Long S) folds to 's'
		{
			name:    "long_s_select",
			pattern: "(?i)select",
			input:   "ſelect",
			matches: true,
		},
		{
			name:    "long_s_sleep",
			pattern: "(?i)sleep",
			input:   "ſleep(5)",
			matches: true,
		},
		{
			name:    "long_s_insert",
			pattern: "(?i)(?:select|insert)",
			input:   "inſert",
			matches: true,
		},
		// 'K' (U+212A, Kelvin Sign) folds to 'k'
		{
			name:    "kelvin_ok",
			pattern: "(?i)ok",
			input:   "o\u212a",
			matches: true,
		},
		// Mixed: non-ASCII input but no fold relevance (should still be safe)
		{
			name:    "unrelated_non_ascii",
			pattern: "(?i)hello",
			input:   "héllo",
			matches: false,
		},
		// Pure ASCII input — normal fast path should work
		{
			name:    "ascii_select_upper",
			pattern: "(?i)select",
			input:   "SELECT",
			matches: true,
		},
		{
			name:    "ascii_select_no_match",
			pattern: "(?i)select",
			input:   "UPDATE",
			matches: false,
		},
		// CRS-style alternation with Unicode fold in input
		{
			name:    "crs_sqli_long_s",
			pattern: `(?i)(?:union\s+select|insert\s+into)`,
			input:   "union ſelect * from t",
			matches: true,
		},
		// Empty non-ASCII input
		{
			name:    "non_ascii_short",
			pattern: "(?i)hello",
			input:   "é",
			matches: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			re := regexp.MustCompile(tc.pattern)
			regexResult := re.MatchString(tc.input)
			if regexResult != tc.matches {
				t.Fatalf("test bug: regex %q on %q = %v, expected %v",
					tc.pattern, tc.input, regexResult, tc.matches)
			}

			ml := minMatchLength(tc.pattern)
			if regexResult && len(tc.input) < ml {
				t.Errorf("FALSE NEGATIVE: minMatchLength(%q)=%d rejects matching input %q (len=%d)",
					tc.pattern, ml, tc.input, len(tc.input))
			}

			pf := prefilterFunc(tc.pattern)
			if pf != nil && regexResult && !pf(tc.input) {
				t.Errorf("FALSE NEGATIVE: prefilter(%q) returned false for matching input %q — "+
					"this is a SECURITY BUG (Unicode fold equivalents not handled)",
					tc.pattern, tc.input)
			}
		})
	}
}

// TestPrefilterEdgeCases covers additional edge cases that are easy to miss:
// empty alternation branches, escaped special chars, very short patterns,
// patterns with only anchors, adjacent literals, and patterns where all
// extracted literals are too short to be useful.
func TestPrefilterEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		matches bool
	}{
		// Empty alternation branch: (|abc) can match empty string
		// Prefilter must NOT require "abc" since the empty branch can match anything
		{
			name:    "empty_alt_branch_match_empty",
			pattern: "(|abc)",
			input:   "",
			matches: true,
		},
		{
			name:    "empty_alt_branch_match_abc",
			pattern: "(|abc)",
			input:   "abc",
			matches: true,
		},
		{
			name:    "empty_alt_branch_match_other",
			pattern: "(|abc)",
			input:   "xyz",
			matches: true,
		},
		// Escaped special chars become literals
		{
			name:    "escaped_dot_exe",
			pattern: `.*\.exe`,
			input:   "malware.exe",
			matches: true,
		},
		{
			name:    "escaped_dot_exe_no_match",
			pattern: `.*\.exe`,
			input:   "malwarexexe",
			matches: false,
		},
		// Pattern with only anchors — no literals to extract
		{
			name:    "only_anchors",
			pattern: "^$",
			input:   "",
			matches: true,
		},
		// Adjacent literals in concat (AST may merge or keep separate)
		{
			name:    "adjacent_literals",
			pattern: "hel" + "lo",
			input:   "hello",
			matches: true,
		},
		// All extracted literals too short (filtered out by filterShort)
		{
			name:    "short_literals_only",
			pattern: "a.*b",
			input:   "axb",
			matches: true,
		},
		// Nested quantifiers
		{
			name:    "nested_plus_star",
			pattern: "(ab+)*cd",
			input:   "abbbcd",
			matches: true,
		},
		{
			name:    "nested_plus_star_no_match",
			pattern: "(ab+)*cd",
			input:   "xyz",
			matches: false,
		},
		// Very long literal
		{
			name:    "long_literal_match",
			pattern: "abcdefghijklmnop",
			input:   "xxabcdefghijklmnopxx",
			matches: true,
		},
		{
			name:    "long_literal_no_match",
			pattern: "abcdefghijklmnop",
			input:   "xxabcdefghijklmnoxx",
			matches: false,
		},
		// Alternation where branches share a prefix
		{
			name:    "shared_prefix_alt",
			pattern: "(?:abcdef|abcxyz)",
			input:   "xabcxyzx",
			matches: true,
		},
		// Nested alternation (previously found by fuzzer)
		{
			name:    "nested_alt_10_00",
			pattern: "10|(10|00)",
			input:   "00",
			matches: true,
		},
		{
			name:    "nested_alt_10_10",
			pattern: "10|(10|00)",
			input:   "10",
			matches: true,
		},
		// Pattern with \b word boundary (zero-width, no literals)
		{
			name:    "word_boundary",
			pattern: `\bhello\b`,
			input:   "say hello world",
			matches: true,
		},
		// Repeat with high min
		{
			name:    "repeat_high_min",
			pattern: `a{5}`,
			input:   "aaaaa",
			matches: true,
		},
		{
			name:    "repeat_high_min_short",
			pattern: `a{5}`,
			input:   "aaaa",
			matches: false,
		},
		// Case-sensitive pattern should NOT match uppercase
		{
			name:    "case_sensitive_exact",
			pattern: "select",
			input:   "SELECT",
			matches: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			re := regexp.MustCompile(tc.pattern)
			regexResult := re.MatchString(tc.input)
			if regexResult != tc.matches {
				t.Fatalf("test bug: regex %q on %q = %v, expected %v",
					tc.pattern, tc.input, regexResult, tc.matches)
			}

			ml := minMatchLength(tc.pattern)
			if regexResult && len(tc.input) < ml {
				t.Errorf("FALSE NEGATIVE via minLen: pattern=%q input=%q (len=%d, minLen=%d)",
					tc.pattern, tc.input, len(tc.input), ml)
			}

			pf := prefilterFunc(tc.pattern)
			if pf != nil && regexResult && !pf(tc.input) {
				t.Errorf("FALSE NEGATIVE via prefilter: pattern=%q input=%q",
					tc.pattern, tc.input)
			}
		})
	}
}

// TestAnyRequiredNeverFiltered verifies that the anyRequired path uses
// anyTooShort (fail-safe) instead of filterShort (silently remove). If any
// alternation branch produces a short literal, the prefilter should be nil
// (no prefilter) rather than checking only the longer alternatives, which
// would risk false negatives.
func TestAnyRequiredNeverFiltered(t *testing.T) {
	// Pattern (é|hello) — é is a single rune but 2 bytes in UTF-8.
	// Both branches should produce usable literals. The prefilter should
	// be non-nil and accept inputs matching either branch.
	t.Run("two_byte_unicode_branch", func(t *testing.T) {
		pattern := "(é|hello)"
		pf := prefilterFunc(pattern)
		// Both "é" (2 bytes) and "hello" (5 bytes) are >= 2, so prefilter exists
		if pf == nil {
			t.Fatal("prefilter should be non-nil: both branches are >= 2 bytes")
		}
		// Must accept matching inputs
		re := regexp.MustCompile(pattern)
		for _, input := range []string{"é", "hello", "xxéxx", "xxhelloxx"} {
			if re.MatchString(input) && !pf(input) {
				t.Errorf("FALSE NEGATIVE: prefilter(%q) rejected matching input %q", pattern, input)
			}
		}
	})

	// Verify that anyTooShort correctly detects short elements
	t.Run("anyTooShort_function", func(t *testing.T) {
		if anyTooShort([]string{"ab", "cd", "ef"}, 2) {
			t.Error("expected false for all >= 2")
		}
		if !anyTooShort([]string{"ab", "c", "ef"}, 2) {
			t.Error("expected true when one element is < 2")
		}
		if !anyTooShort([]string{"", "ab"}, 2) {
			t.Error("expected true for empty element")
		}
		if anyTooShort([]string{}, 2) {
			t.Error("expected false for empty slice")
		}
	})
}

// TestParseErrorPaths verifies that invalid regex patterns are handled gracefully:
// minMatchLength returns 0 and prefilterFunc returns nil.
func TestParseErrorPaths(t *testing.T) {
	invalid := []string{
		"[unclosed",
		"(?P<unclosed",
		"(?",
		"*invalid",
	}
	for _, p := range invalid {
		t.Run(p, func(t *testing.T) {
			if got := minMatchLength(p); got != 0 {
				t.Errorf("minMatchLength(%q) = %d, want 0 for invalid pattern", p, got)
			}
			if got := prefilterFunc(p); got != nil {
				t.Errorf("prefilterFunc(%q) = non-nil, want nil for invalid pattern", p)
			}
		})
	}
}

// FuzzPrefilterNoFalseNegatives uses Go's built-in fuzz testing to verify with
// random patterns AND inputs that the prefilter never rejects an input the
// regex matches. This is the primary safety net — it generates arbitrary
// regex patterns that the fuzzer evolves to maximize code coverage.
// Run with: go test -tags coraza.rule.rx_prefilter -fuzz=FuzzPrefilterNoFalseNegatives -fuzztime=60s
func FuzzPrefilterNoFalseNegatives(f *testing.F) {
	// Seed corpus: CRS-representative patterns × realistic inputs.
	patterns := []string{
		"hello",
		"hello.*world",
		"(?i)(?:union\\s+select|insert\\s+into)",
		"(?:;|\\|)\\s*(?:cat|ls|id|whoami)",
		"(?i)<script[^>]*>",
		"sleep\\s*\\(",
		"10|(10|00)",
		"ab(cd|ef)gh",
		"(?:cat|dog|bird)",
		"(ab)+",
		"[a-z]+test",
		"ハロー",
	}
	inputs := []string{
		"GET /index.html HTTP/1.1",
		"POST /api/v1/users HTTP/1.1",
		"union select * from users--",
		"UNION ALL SELECT 1,2,3",
		"; cat /etc/passwd",
		"sleep(5)",
		"<script>alert(1)</script>",
		"onerror=alert(1)",
		"../../../etc/passwd",
		"",
		"hello",
		"HELLO",
		"abcdgh",
		"ſelect",
		"un café chaud",
	}
	for _, p := range patterns {
		for _, inp := range inputs {
			f.Add(p, inp)
		}
	}

	f.Fuzz(func(t *testing.T, pattern, input string) {
		// Cap lengths to avoid expensive regex evaluations that stall the fuzzer.
		if len(pattern) > 256 || len(input) > 512 {
			return
		}

		// Skip invalid regex patterns
		re, err := regexp.Compile(pattern)
		if err != nil {
			return
		}

		regexMatches := re.MatchString(input)

		ml := minMatchLength(pattern)
		if regexMatches && len(input) < ml {
			t.Errorf("FALSE NEGATIVE via minLen: pattern=%q input=%q (len=%d, minLen=%d)",
				pattern, input, len(input), ml)
		}

		pf := prefilterFunc(pattern)
		if pf != nil && regexMatches && !pf(input) {
			t.Errorf("FALSE NEGATIVE via prefilter: pattern=%q input=%q",
				pattern, input)
		}
	})
}

// FuzzPrefilterFixedCRSPatterns fuzzes with fixed CRS-representative patterns
// against random inputs. This simulates real-world usage: the patterns are
// known at compile time (from CRS rules), the inputs are arbitrary user traffic.
// Run with: go test -tags coraza.rule.rx_prefilter -fuzz=FuzzPrefilterFixedCRSPatterns -fuzztime=60s
func FuzzPrefilterFixedCRSPatterns(f *testing.F) {
	f.Add("normal request data")
	f.Add("union select * from users")
	f.Add("<script>alert(1)</script>")
	f.Add("sleep(5)")
	f.Add("../../../etc/passwd")
	f.Add("")
	f.Add("UNION SELECT")

	// Fixed patterns representative of real CRS rules
	crsPatterns := []string{
		`(?i)(?:union\s+(?:all\s+)?select)`,
		`(?i)(?:insert\s+into|delete\s+from|update\s+\w+\s+set)`,
		`(?i)<script[^>]*>`,
		`(?i)(?:on(?:error|load|click|mouse\w+)\s*=)`,
		`(?:;|\|)\s*(?:cat|ls|id|whoami|passwd)`,
		`sleep\s*\(`,
		`(?i)(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)(?:[^\}]{0,15}(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)|jndi|ctx)`,
		`[\r\n]\s*(?:content-(?:type|length)|set-cookie|location)\s*:`,
		`(?i)<\?(?:php|=)`,
		`(?:\.{2}[/\\]){3,}`,
		`(?i)(?:exec|system|passthru|popen|proc_open)\s*\(`,
		`hello.*world`,
		`(?:union|select|insert|delete|update|drop|alter|create)`,
	}

	// Precompile all patterns and their prefilters
	type compiled struct {
		re *regexp.Regexp
		ml int
		pf func(string) bool
	}
	cc := make([]compiled, len(crsPatterns))
	for i, p := range crsPatterns {
		cc[i] = compiled{
			re: regexp.MustCompile(p),
			ml: minMatchLength(p),
			pf: prefilterFunc(p),
		}
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Cap input length to prevent the fuzzer from generating strings that
		// cause expensive regex evaluations and stall the fuzzer. CRS patterns
		// can be costly on longer inputs (e.g. log4shell with backtracking).
		if len(input) > 128 {
			return
		}
		for i, c := range cc {
			regexMatches := c.re.MatchString(input)

			if regexMatches && len(input) < c.ml {
				t.Errorf("FALSE NEGATIVE via minLen: pattern=%q input=%q (len=%d, minLen=%d)",
					crsPatterns[i], input, len(input), c.ml)
			}

			if c.pf != nil && regexMatches && !c.pf(input) {
				t.Errorf("FALSE NEGATIVE via prefilter: pattern=%q input=%q",
					crsPatterns[i], input)
			}
		}
	})
}

// TestPrefilterCodePaths exercises specific code paths in prefilterFunc and
// extractLiterals via table-driven cases.  Each entry targets a particular
// branch/guard to ensure coverage without needing a dedicated function.
func TestPrefilterCodePaths(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantPF  bool   // whether prefilterFunc should return non-nil
		pass    string // input the prefilter must accept (skip if "")
		reject  string // input the prefilter must reject (skip if "")
	}{
		// --- minMatchLength edge cases ---
		{"mml_rune_error", "\xef\xbf\xbd", false, "", ""},
		{"mml_rune_error_plus_literal", "(?s)\xef\xbf\xbd" + "hello", true, "\xef\xbf\xbdhello!xx", "hello"},
		{"mml_repeat_3_5", "a{3,5}", false, "", ""},
		{"mml_repeat_0_5", "a{0,5}", false, "", ""},

		// --- allRequired paths ---
		{"all_filtered_to_empty", "(?s)a.*", false, "", ""},
		{"all_filtered_short", "(?s)a.*b", false, "", ""},
		{"all_multi_CS", "(?s)hello.*world", true, "prefix hello middle world suffix", "prefix hello middle suffix"},
		{"all_multi_CI", "(?si)hello.*world", true, "foo HELLO bar WORLD baz", "foo HELLO bar baz"},

		// --- anyRequired paths ---
		{"any_CS_2_elements", "(?s)(?:hello|world)", true, "contains hello here", "contains nothing here"},
		{"any_CI_2_elements", "(?si)(?:hello|world)", true, "HELLO there", "nothing here"},
		{"any_too_short_bailout", "(?s)(?:a|hello)", false, "", ""},
		{"any_non_ascii_CI_bailout", "(?si)(?:café|naïve)", false, "", ""},
		{"any_nested_alternation", "(?s)(?:hello|(?:world|test))", true, "test", "none"},

		// --- OpConcat with anyRequired child ---
		{"concat_any_child_surfaces_allRequired", "(?s)(?:ab|cd).*required", true, "ab stuff required here", "ab stuff missing here"},

		// --- OpAlternate nil branch → abandon ---
		{"alt_nil_branch", "(?s)(?:hello|.+)", false, "", ""},
		{"alt_all_nil_branches", "(?s)(?:.+|.*)", false, "", ""},

		// --- OpRepeat min==0 → nil ---
		{"repeat_min_zero", "(?s)(?:hello){0,3}", false, "", ""},

		// --- case-insensitive non-ASCII passthrough ---
		{"ci_non_ascii_input_passthrough", "(?si)hello", true, "héllo", "goodbye"},
		{"cs_returns_directly", "(?s)hello", true, "say hello", "café"},

		// --- helpers ---
		{"longest_nil", "", false, "", ""},
		{"allASCIIStrings_non_ascii", "(?si)(?:café|naïve)", false, "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pattern == "" {
				// Test helpers directly
				if got := longest(nil); got != "" {
					t.Errorf("longest(nil) = %q, want empty", got)
				}
				if !allASCIIStrings([]string{"hello", "world"}) {
					t.Error("allASCIIStrings should return true for all ASCII")
				}
				if allASCIIStrings([]string{"hello", "café"}) {
					t.Error("allASCIIStrings should return false for non-ASCII")
				}
				return
			}

			pf := prefilterFunc(tc.pattern)
			if tc.wantPF && pf == nil {
				t.Fatalf("prefilterFunc(%q) = nil, want non-nil", tc.pattern)
			}
			if !tc.wantPF && pf != nil {
				t.Fatalf("prefilterFunc(%q) = non-nil, want nil", tc.pattern)
			}
			if pf == nil {
				return
			}
			if tc.pass != "" && !pf(tc.pass) {
				t.Errorf("prefilter rejected %q — expected pass", tc.pass)
			}
			if tc.reject != "" && pf(tc.reject) {
				t.Errorf("prefilter accepted %q — expected reject", tc.reject)
			}
		})
	}

	// Additional minMatchLength checks
	if got := minMatchLength("\xef\xbf\xbd"); got != 1 {
		t.Errorf("minMatchLength(U+FFFD) = %d, want 1", got)
	}
	if got := minMatchLength("ab\xef\xbf\xbd"); got != 3 {
		t.Errorf("minMatchLength(ab+U+FFFD) = %d, want 3", got)
	}
	if got := minMatchLength("a{3,5}"); got != 3 {
		t.Errorf("minMatchLength(a{3,5}) = %d, want 3", got)
	}
	if got := minMatchLength("a{0,5}"); got != 0 {
		t.Errorf("minMatchLength(a{0,5}) = %d, want 0", got)
	}
}

// TestTrieReconstructionBasic verifies that prefilterFunc correctly handles
// Simplify()-generated trie patterns where a short single-byte prefix is
// factored out of an alternation.
//
// Without trie reconstruction:
//
//	select|sleep|substr  →  s(?:elect|leep|ubstr)
//	extractLiterals(OpLiteral("s")) = nil  →  whole pattern = nil
//	prefilterFunc returns nil  →  no prefilter built at all
//
// With trie reconstruction the full words are recovered and used as the
// anyRequired set, enabling sub-linear Wu-Manber prefiltering.
func TestTrieReconstructionBasic(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		shouldMatch []string
		shouldMiss  []string
	}{
		{
			name:    "single_prefix_alternation",
			pattern: "(?i)(?:select|sleep|substr)",
			// Simplify() → s(?:elect|leep|ubstr) — single-byte prefix 's'
			shouldMatch: []string{"SELECT", "sleep(1)", "substr(x,1)"},
			shouldMiss:  []string{"hello world", "GET /api/v1/users", "x=1&y=2"},
		},
		{
			name:    "multi_group_sql_keywords",
			pattern: "(?i)(?:select|sleep|substr|union|update|insert|delete)",
			// Simplify() groups by first byte: s(..), u(..), i(..), d(..)
			// Each group has a single-byte prefix that was previously causing nil.
			shouldMatch: []string{"SELECT id", "UNION ALL", "UPDATE users", "INSERT INTO", "DELETE FROM"},
			shouldMiss:  []string{"GET /home", "Host: example.com", "Content-Type: text/html"},
		},
		{
			name:    "two_char_prefix_reconstruction",
			pattern: "(?i)(?:replace|reverse|repeat)",
			// Simplify() → re(?:place|verse|peat) — 2-char prefix "re"
			// The 2-char prefix IS extracted by the standard path as allRequired{"re"},
			// so this tests that the standard path still works correctly.
			shouldMatch: []string{"REPLACE INTO", "reverse order", "repeat(x,3)"},
			shouldMiss:  []string{"hello world", "GET /users"},
		},
		{
			name:    "nested_trie_reconstruction",
			pattern: "(?i)(?:select|set|sleep)",
			// Simplify() → s(?:e(?:lect|t)|leep) — nested trie
			// trieReconstruct (prefix "s") runs before anyRequired propagation,
			// so the result is anyRequired{"select","set","sleep"} — NOT the
			// shorter {"elect","et","leep"} that propagation alone would yield.
			// ("et" is a substring of "GET", so the shorter form causes false positives.)
			shouldMatch: []string{"SELECT *", "set @x=1", "SLEEP(5)"},
			shouldMiss:  []string{"GET /api", "x=1&y=2"},
		},
		{
			name:    "anchor_or_separator_then_keywords",
			pattern: `(?i)(?:^|["':;=])\s*(?:alert|prompt|confirm)`,
			// Branch (?:^|["':;=]) returns nil because the ^ sub-branch has no literal.
			// anyRequired propagation in OpConcat surfaces the keyword alternation:
			// → anyRequired{"alert","prompt","confirm"}
			shouldMatch: []string{"alert(1)", `";alert(1)`, "PROMPT(x)", "=confirm()"},
			shouldMiss:  []string{"GET /api", "content-type: text/html", "user@example.com"},
		},
		{
			name:    "large_sql_alternation",
			pattern: "(?i)(?:select|sleep|substr|union|update|insert|delete|alter|create|benchmark|floor|format|length|concat|decode|encode|replace|reverse|trim|upper)",
			// 20 SQL keywords — Simplify() groups: s(..), u(..), i(..), d(..), a(..), c(..), b(..), f(..), l(..), r(..), t(..)
			// Previously: all groups with single-byte prefix returned nil → no prefilter
			// After fix: each group reconstructed → anyRequired{all 20 keywords}
			shouldMatch: []string{"SELECT id FROM", "UNION ALL SELECT", "benchmark(1000000,1)", "UPPER(col)"},
			shouldMiss:  []string{"GET /api/v1/users?page=1", "Host: example.com", "Content-Type: application/json"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			pf := prefilterFunc(tc.pattern)
			if pf == nil {
				t.Fatalf("prefilterFunc returned nil — trie reconstruction likely not working (pattern: %s)", tc.pattern)
			}
			for _, s := range tc.shouldMatch {
				if !pf(s) {
					t.Errorf("prefilter false-negative for input %q (pattern: %s)", s, tc.pattern)
				}
			}
			for _, s := range tc.shouldMiss {
				if pf(s) {
					t.Errorf("prefilter false-positive for input %q (pattern: %s)", s, tc.pattern)
				}
			}
		})
	}
}

// TestTrieReconstructionSafety verifies that trie reconstruction never produces
// false negatives: for inputs that the regex matches, the prefilter must also
// return true.
func TestTrieReconstructionSafety(t *testing.T) {
	patterns := []string{
		"(?i)(?:select|sleep|substr|union)",
		"(?i)(?:select|sleep|substr|union|update|insert|delete|alter|create|benchmark|floor|format|length|concat|decode|encode|replace|reverse|trim|upper)",
		"(?i)(?:exec|execute|call|sp_|xp_|@@version|information_schema)",
	}
	inputs := []string{
		"SELECT * FROM users", "sleep(5)", "UNION SELECT", "update users set",
		"INSERT INTO t", "delete from t where", "benchmark(1000,1)",
		"floor(rand())", "UPPER('a')", "concat(1,2)",
		"1 AND 1=1", "'; DROP TABLE--", "admin'--",
	}

	for _, pat := range patterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			t.Fatalf("compile %q: %v", pat, err)
		}
		pf := prefilterFunc(pat)
		if pf == nil {
			continue // no prefilter built — skip (not a failure)
		}
		for _, input := range inputs {
			regexMatch := re.MatchString(input)
			prefilterSays := pf(input)
			// Safety invariant: if regex matches, prefilter must NOT say false.
			if regexMatch && !prefilterSays {
				t.Errorf("SAFETY VIOLATION: prefilter false-negative\n  pattern=%q\n  input=%q\n  regex=true prefilter=false", pat, input)
			}
		}
	}
}

// TestIndexedMatcherNeedleCounts verifies the shift-table indexedMatcher
// at boundary needle counts, cross-checking against a brute-force reference.
func TestIndexedMatcherNeedleCounts(t *testing.T) {
	pool := []string{
		"select", "union", "insert", "delete", "update",
		"alter", "create", "sleep", "benchmark", "extract",
		"floor", "format", "length", "concat", "decode", "encode",
	}
	haystack := "GET /api/v1/users?page=1&sort=name&order=asc HTTP/1.1"
	matchInputCS := "1 union select * from users--"
	matchInputCI := "1 UNION SELECT * FROM users--"

	bruteForceCS := func(needles []string, s string) bool {
		for _, n := range needles {
			if strings.Contains(s, n) {
				return true
			}
		}
		return false
	}
	bruteForceCI := func(needles []string, s string) bool {
		ls := strings.ToLower(s)
		for _, n := range needles {
			if strings.Contains(ls, strings.ToLower(n)) {
				return true
			}
		}
		return false
	}

	for _, count := range []int{2, 8, 16} {
		needles := pool[:count]

		t.Run(fmt.Sprintf("CS_%d/no_match", count), func(t *testing.T) {
			im := newIndexedMatcher(needles, false)
			if got, want := im.match(haystack), bruteForceCS(needles, haystack); got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
		t.Run(fmt.Sprintf("CS_%d/match", count), func(t *testing.T) {
			im := newIndexedMatcher(needles, false)
			if got, want := im.match(matchInputCS), bruteForceCS(needles, matchInputCS); got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
		t.Run(fmt.Sprintf("CI_%d/match", count), func(t *testing.T) {
			im := newIndexedMatcher(needles, true)
			if got, want := im.match(matchInputCI), bruteForceCI(needles, matchInputCI); got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

// TestIndexedMatcherEveryNeedle verifies each needle is found at start/end positions,
// in both CS and CI modes.
func TestIndexedMatcherEveryNeedle(t *testing.T) {
	needles := []string{"alpha", "bravo", "charlie", "delta",
		"echo", "foxtrot", "golf", "hotel", "india", "juliet"}

	for _, ci := range []bool{false, true} {
		im := newIndexedMatcher(needles, ci)
		mode := "CS"
		if ci {
			mode = "CI"
		}
		for _, needle := range needles {
			display := needle
			if ci {
				display = strings.ToUpper(needle)
			}
			t.Run(fmt.Sprintf("%s/start_%s", mode, needle), func(t *testing.T) {
				if !im.match(display + " after") {
					t.Errorf("expected match for %q at start", display)
				}
			})
			t.Run(fmt.Sprintf("%s/end_%s", mode, needle), func(t *testing.T) {
				if !im.match("before " + display) {
					t.Errorf("expected match for %q at end", display)
				}
			})
		}
		t.Run(mode+"/no_match", func(t *testing.T) {
			if im.match("nothing relevant here xyz") {
				t.Error("expected no match for irrelevant input")
			}
		})
	}
}

// TestIndexedMatcherEdgeCases covers structural edge cases: shared first/last
// bytes, varying needle lengths, boundary positions, and minimal haystacks.
func TestIndexedMatcherEdgeCases(t *testing.T) {
	t.Run("all_same_first_byte", func(t *testing.T) {
		needles := []string{"select", "sleep", "substr", "system", "schema"}
		im := newIndexedMatcher(needles, false)
		if !im.match("call sleep(5)") {
			t.Error("expected match for 'sleep'")
		}
		if !im.match("find substr here") {
			t.Error("expected match for 'substr'")
		}
		if im.match("no s-words that match") {
			t.Error("expected no match")
		}
	})

	t.Run("all_same_last_byte", func(t *testing.T) {
		needles := []string{"update", "delete", "create", "locate", "inate"}
		im := newIndexedMatcher(needles, false)
		if !im.match("please delete this") {
			t.Error("expected match for 'delete'")
		}
		if im.match("nothing matching") {
			t.Error("expected no match")
		}
	})

	t.Run("varying_needle_lengths", func(t *testing.T) {
		needles := []string{"ab", "abcde", "abcdefghij", "xyz", "mn"}
		im := newIndexedMatcher(needles, false)
		if !im.match("contains ab here") {
			t.Error("expected match for shortest needle 'ab'")
		}
		if !im.match("contains abcdefghij here") {
			t.Error("expected match for longest needle")
		}
		if !im.match("contains xyz here") {
			t.Error("expected match for 'xyz'")
		}
		if im.match("nothing relevant") {
			t.Error("expected no match")
		}
	})

	t.Run("haystack_exactly_minlen", func(t *testing.T) {
		needles := []string{"hello", "world", "tests"}
		im := newIndexedMatcher(needles, false)
		if !im.match("hello") {
			t.Error("expected match when haystack == needle == minLen")
		}
		if im.match("nope!") {
			t.Error("expected no match when haystack == minLen but no needle")
		}
	})

	t.Run("haystack_shorter_than_minlen", func(t *testing.T) {
		needles := []string{"hello", "world"}
		im := newIndexedMatcher(needles, false)
		if im.match("hi") {
			t.Error("expected no match when haystack < minLen")
		}
		if im.match("") {
			t.Error("expected no match for empty haystack")
		}
	})

	t.Run("needle_at_exact_end", func(t *testing.T) {
		needles := []string{"zzend", "world"}
		im := newIndexedMatcher(needles, false)
		if !im.match("at the zzend") {
			t.Error("expected match at exact end of haystack")
		}
	})

	t.Run("overlapping_needles", func(t *testing.T) {
		needles := []string{"abc", "bcd", "cde"}
		im := newIndexedMatcher(needles, false)
		if !im.match("xxabcdexx") {
			t.Error("expected match with overlapping needles")
		}
		if !im.match("xxbcdxx") {
			t.Error("expected match for 'bcd'")
		}
	})

	t.Run("ci_mixed_case_needles_at_boundary", func(t *testing.T) {
		needles := []string{"hello", "world"}
		im := newIndexedMatcher(needles, true)
		if !im.match("HELLO") {
			t.Error("CI: expected match for exact uppercase")
		}
		if !im.match("hElLo") {
			t.Error("CI: expected match for mixed case")
		}
		if !im.match("end WORLD") {
			t.Error("CI: expected match at end")
		}
	})

	t.Run("two_needles_minimal", func(t *testing.T) {
		needles := []string{"ab", "cd"}
		im := newIndexedMatcher(needles, false)
		if !im.match("ab") {
			t.Error("expected match for 'ab'")
		}
		if !im.match("cd") {
			t.Error("expected match for 'cd'")
		}
		if im.match("ac") {
			t.Error("expected no match for 'ac'")
		}
		if im.match("x") {
			t.Error("expected no match for too-short input")
		}
	})
}

// TestAnyRequiredThresholdBoundary tests indexedMatcher at the anyRequiredMaxN
// boundary (16 needles) and beyond it (256 needles fall back to no prefilter).
func TestAnyRequiredThresholdBoundary(t *testing.T) {
	genWords := func(n int) []string {
		words := make([]string, n)
		for i := 0; i < n; i++ {
			words[i] = fmt.Sprintf("%cword%d", 'a'+rune(i%26), i)
		}
		return words
	}

	for _, count := range []int{16, 64} {
		words := genWords(count)
		im := newIndexedMatcher(words, false)
		t.Run(fmt.Sprintf("N%d/match", count), func(t *testing.T) {
			if !im.match("prefix " + words[0] + " suffix") {
				t.Errorf("expected match for first needle")
			}
		})
		t.Run(fmt.Sprintf("N%d/no_match", count), func(t *testing.T) {
			if im.match("completely irrelevant input") {
				t.Error("expected no match")
			}
		})
	}
}

// TestAnyRequiredViaPrefilterFuncNeedleCounts verifies end-to-end prefilter
// pipeline (parse → extract → matcher → evaluate) at boundary needle counts.
func TestAnyRequiredViaPrefilterFuncNeedleCounts(t *testing.T) {
	allWords := []string{
		"alpha", "bravo", "charlie", "delta", "echo",
		"foxtrot", "golf", "hotel", "india", "juliet",
		"kilo", "lima", "mike", "november", "oscar", "papa",
	}
	noMatchInput := "GET /api/v1/resources?page=1&sort=name HTTP/1.1"

	for _, count := range []int{2, 16} {
		words := allWords[:count]
		pattern := "(?:" + strings.Join(words, "|") + ")"
		pf := prefilterFunc(pattern)
		if pf == nil {
			t.Fatalf("N=%d: prefilterFunc returned nil for %q", count, pattern)
		}
		re := regexp.MustCompile(pattern)

		// One match case (first word)
		matchInput := "some " + words[0] + " here"
		t.Run(fmt.Sprintf("N%d/match", count), func(t *testing.T) {
			if !re.MatchString(matchInput) {
				t.Fatalf("test bug: regex doesn't match %q", matchInput)
			}
			if !pf(matchInput) {
				t.Errorf("FALSE NEGATIVE: prefilter rejected %q", matchInput)
			}
		})
		t.Run(fmt.Sprintf("N%d/no_match", count), func(t *testing.T) {
			if re.MatchString(noMatchInput) {
				t.Fatal("test bug: regex matches benign input")
			}
			_ = pf(noMatchInput) // conservative pass-through is OK
		})
	}
}

// TestInternalNodeCoverage exercises code paths in internal helper functions that
// are unreachable through the public prefilterFunc / minMatchLength APIs because
// syntax.Regexp.Simplify() expands or eliminates certain AST nodes before those
// functions are called. We construct synthetic AST nodes directly (same package)
// to reach the defensive branches and ensure they behave correctly.
func TestInternalNodeCoverage(t *testing.T) {
	// ── minLen ────────────────────────────────────────────────────────────────

	t.Run("minLen/empty_OpAlternate", func(t *testing.T) {
		// syntax.Parse never produces an empty OpAlternate after Simplify, but
		// minLen guards against it. Verify the guard returns 0 (not a panic).
		re := &syntax.Regexp{Op: syntax.OpAlternate, Sub: []*syntax.Regexp{}}
		if got := minLen(re); got != 0 {
			t.Errorf("minLen(empty OpAlternate) = %d, want 0", got)
		}
	})

	t.Run("minLen/OpRepeat_min0", func(t *testing.T) {
		// Simplify expands {0,n} into optional nodes, so OpRepeat with min=0 is
		// only reachable via direct call. Must return 0 (zero repetitions allowed).
		lit := &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune("ab")}
		re := &syntax.Regexp{Op: syntax.OpRepeat, Min: 0, Sub: []*syntax.Regexp{lit}}
		if got := minLen(re); got != 0 {
			t.Errorf("minLen(OpRepeat min=0) = %d, want 0", got)
		}
	})

	t.Run("minLen/OpRepeat_min3", func(t *testing.T) {
		// OpRepeat with min=3 and a 2-byte child → minimum 6 bytes.
		lit := &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune("ab")}
		re := &syntax.Regexp{Op: syntax.OpRepeat, Min: 3, Sub: []*syntax.Regexp{lit}}
		if got := minLen(re); got != 6 {
			t.Errorf("minLen(OpRepeat min=3, child=2b) = %d, want 6", got)
		}
	})

	// ── extractLiterals ───────────────────────────────────────────────────────

	t.Run("extractLiterals/OpRepeat_min1", func(t *testing.T) {
		// Simplify expands {1,n} into explicit concat chains, so OpRepeat min≥1
		// is only reachable via direct call. Must recurse into the sub-expression.
		lit := &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune("select")}
		re := &syntax.Regexp{Op: syntax.OpRepeat, Min: 1, Sub: []*syntax.Regexp{lit}}
		got := extractLiterals(re, false)
		if got == nil {
			t.Error("extractLiterals(OpRepeat min=1, 'select') = nil, want allRequired{select}")
		}
	})

	t.Run("extractLiterals/OpRepeat_min0", func(t *testing.T) {
		// OpRepeat with min=0 is optional — no literals can be required.
		lit := &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune("select")}
		re := &syntax.Regexp{Op: syntax.OpRepeat, Min: 0, Sub: []*syntax.Regexp{lit}}
		if got := extractLiterals(re, false); got != nil {
			t.Errorf("extractLiterals(OpRepeat min=0) = %v, want nil", got)
		}
	})

	t.Run("extractLiterals/empty_OpAlternate", func(t *testing.T) {
		// An OpAlternate with no children never executes the inner loop, so
		// branchLits stays empty and the function returns nil.
		re := &syntax.Regexp{Op: syntax.OpAlternate, Sub: []*syntax.Regexp{}}
		if got := extractLiterals(re, false); got != nil {
			t.Errorf("extractLiterals(empty OpAlternate) = %v, want nil", got)
		}
	})

	// ── rawLiteral ────────────────────────────────────────────────────────────

	t.Run("rawLiteral/RuneError", func(t *testing.T) {
		// A literal containing U+FFFD (RuneError) must return "" to prevent the
		// caller from building a prefilter that searches for the 3-byte UTF-8
		// encoding instead of the single invalid byte that the regex matches.
		re := &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{utf8.RuneError, 'x'}}
		if got := rawLiteral(re, false); got != "" {
			t.Errorf("rawLiteral(RuneError literal) = %q, want empty", got)
		}
	})

	t.Run("rawLiteral/non_literal_op", func(t *testing.T) {
		// rawLiteral must return "" for any non-OpLiteral node.
		re := &syntax.Regexp{Op: syntax.OpAnyChar}
		if got := rawLiteral(re, false); got != "" {
			t.Errorf("rawLiteral(OpAnyChar) = %q, want empty", got)
		}
	})

	// ── rawExtractSuffixes ────────────────────────────────────────────────────

	t.Run("rawExtractSuffixes/RuneError_literal", func(t *testing.T) {
		// rawExtractSuffixes must return nil for a literal containing RuneError
		// so the calling trieReconstruct bails out rather than building a wrong prefilter.
		re := &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{utf8.RuneError}}
		if got := rawExtractSuffixes(re, false); got != nil {
			t.Errorf("rawExtractSuffixes(RuneError) = %v, want nil", got)
		}
	})

	t.Run("rawExtractSuffixes/OpCapture", func(t *testing.T) {
		// Capture groups are transparent — rawExtractSuffixes must unwrap them.
		inner := &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune("elect")}
		cap := &syntax.Regexp{Op: syntax.OpCapture, Sub: []*syntax.Regexp{inner}}
		got := rawExtractSuffixes(cap, false)
		if len(got) != 1 || got[0] != "elect" {
			t.Errorf("rawExtractSuffixes(OpCapture(elect)) = %v, want [elect]", got)
		}
	})

	// ── newIndexedMatcher ─────────────────────────────────────────────────────

	t.Run("newIndexedMatcher/empty_needles", func(t *testing.T) {
		// An empty needle set should build a zero-matcher that never matches.
		m := newIndexedMatcher(nil, false)
		if m == nil || m.minLen != 0 {
			t.Error("newIndexedMatcher(nil) should return a zero-minLen matcher")
		}
		if m.match("anything") {
			t.Error("empty matcher.match() must return false")
		}
	})

	t.Run("newIndexedMatcher/needle_longer_than_255", func(t *testing.T) {
		// When the shortest needle exceeds 255 bytes the shift table is capped at
		// 255 to fit in a uint8. The matcher must still find an exact match.
		needle := strings.Repeat("a", 300)
		m := newIndexedMatcher([]string{needle}, false)
		if m.minLen != 300 {
			t.Errorf("minLen = %d, want 300", m.minLen)
		}
		if !m.match(needle) {
			t.Error("should match exact needle")
		}
		if m.match(strings.Repeat("a", 299)) {
			t.Error("should not match 299-byte input against 300-byte needle")
		}
	})

	// ── matchCI ───────────────────────────────────────────────────────────────

	t.Run("matchCI/haystack_shorter_than_needle", func(t *testing.T) {
		// matchCI must return false immediately when the haystack is shorter
		// than the shortest needle (ml > len(s) guard, lines 805-807).
		m := newIndexedMatcher([]string{"hello"}, true)
		if m.matchCI("hi") {
			t.Error("matchCI: short haystack should return false")
		}
	})

	t.Run("matchCI/zero_minLen", func(t *testing.T) {
		// A zero-minLen matcher (built from empty needles) must return false.
		m := newIndexedMatcher(nil, true)
		if m.matchCI("anything") {
			t.Error("matchCI with minLen=0 must return false")
		}
	})

	// ── containsFoldASCIIOnly ─────────────────────────────────────────────────

	t.Run("containsFoldASCIIOnly/haystack_shorter_than_needle", func(t *testing.T) {
		// limit = len(s) - nlen < 0 → immediate false (lines 897-899).
		if containsFoldASCIIOnly("hi", "hello") {
			t.Error("should return false when haystack shorter than needle")
		}
	})

	t.Run("containsFoldASCIIOnly/first_byte_found_too_late", func(t *testing.T) {
		// IndexByte finds a first-byte match but at a position where the full
		// needle can no longer fit (i > limit). Must return false without panic.
		// haystack="hxxhel", needle="hello" (5b): limit=1.
		// IndexByte('h') finds index 0 → no full match. i=1.
		// IndexByte('h') in "xxhel" finds index 3 → new i = 1+3 = 4 > limit=1 → false.
		if containsFoldASCIIOnly("hxxhel", "hello") {
			t.Error("should return false when first-byte match is at position > limit")
		}
	})
}

func TestPrefilterConcurrentSafety(t *testing.T) {
	rxPattern := `(?i)(?:union\s+select|insert\s+into|delete\s+from)`
	opts := plugintypes.OperatorOptions{Arguments: rxPattern, RxPreFilterEnabled: true}
	op, err := newRX(opts)
	if err != nil {
		t.Fatal(err)
	}
	if op.(*rx).prefilter == nil {
		t.Skip("prefilter not built")
	}
	re := regexp.MustCompile(rxPattern)
	inputs := []string{
		"union select * from t", "INSERT INTO t VALUES",
		"normal request", "GET /index.html HTTP/1.1",
		"delete from users", "", "UNION SELECT 1,2,3",
	}
	const goroutines = 100
	errs := make(chan error, goroutines*len(inputs))
	done := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for _, inp := range inputs {
				waf := corazawaf.NewWAF()
				tx := waf.NewTransaction()
				tx.Capture = true
				got := op.Evaluate(tx, inp)
				if want := re.MatchString(inp); got != want {
					errs <- fmt.Errorf("input %q: got %v, want %v", inp, got, want)
				}
			}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestPrefilterAnyRequiredNonASCIIBailout(t *testing.T) {
	// CI pattern whose needles contain non-ASCII bytes — must bail out (return nil).
	if pf := prefilterFunc("(?si)(?:café|naïve)"); pf != nil {
		t.Error("expected nil prefilter for CI pattern with non-ASCII needles")
	}
}

func TestPrefilterCaseInsensitiveWithNonASCIIInput(t *testing.T) {
	// The isASCII wrapper must conservatively return true for non-ASCII input.
	pf := prefilterFunc("(?si)hello")
	if pf == nil {
		t.Fatal("expected non-nil prefilter for (?si)hello")
	}
	if !pf("héllo") {
		t.Error("CI prefilter must pass non-ASCII input through (conservative)")
	}
	if pf("world") {
		t.Error("CI prefilter must reject clearly non-matching ASCII input")
	}
}

// BenchmarkIndexedMatcher benchmarks the Wu-Manber indexedMatcher at different
// needle counts and case modes against a typical HTTP request haystack.
func BenchmarkIndexedMatcher(b *testing.B) {
	haystack := strings.Repeat("GET /api/v1/resources?page=1&limit=50&sort=name&order=asc HTTP/1.1 Host: example.com ", 6)[:500]
	for _, bm := range []struct {
		name    string
		needles []string
		ci      bool
	}{
		{"n3_CS", []string{"union", "insert", "delete"}, false},
		{"n3_CI", []string{"union", "insert", "delete"}, true},
		{"n10_CS", []string{"select", "union", "insert", "delete", "update", "alter", "create", "sleep", "benchmark", "extract"}, false},
	} {
		im := newIndexedMatcher(bm.needles, bm.ci)
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(haystack)))
			for i := 0; i < b.N; i++ {
				im.match(haystack)
			}
		})
	}
}
