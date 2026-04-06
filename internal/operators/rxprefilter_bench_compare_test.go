//go:build coraza.rule.rx_prefilter

// bench_compare_test.go: apples-to-apples benchmark against main.
//
// Compare with benchstat:
//
//	go test -tags coraza.rule.rx_prefilter -bench BenchmarkCompare \
//	    -benchmem -benchtime=4s -count=6 | tee /tmp/branch.txt
//	benchstat /tmp/main.txt /tmp/branch.txt

package operators

import (
	"regexp"
	"testing"
)

// ---------------------------------------------------------------------------
// Regex patterns grouped by category
// ---------------------------------------------------------------------------

type benchPattern struct {
	name    string
	pattern string
}

var bcPatterns = []benchPattern{
	// Category A: single literal – control group (prefiltered on both branches)
	{
		"A_literal",
		`(?i)(?:union[\s\S]+select|select[\s\S]+from|insert[\s\S]+into)`,
	},

	// Category B: small alternation ≤16 (main: Aho-Corasick; ours: Wu-Manber)
	{
		"B_small_alt_8",
		`(?i)(?:and|or|not|xor|null|true|false|between)`,
	},
	{
		"B_small_alt_16",
		`(?i)(?:select|insert|update|delete|alter|create|drop|union|exec|execute|truncate|replace|merge|call|load|handler)`,
	},

	// Category C: large trie alternation (main: nil; ours: trie-reconstruct)
	{
		"C_trie_20",
		`(?i)(?:select|sleep|substr|union|update|insert|delete|alter|create|benchmark|floor|format|length|concat|decode|encode|replace|reverse|trim|upper)`,
	},
	{
		"C_trie_sqli_big",
		`(?i)(?:and|between|binary|blob|boolean|char|column|concat|convert|count|database|decode|delimiter|describe|distinct|div|double|drop|dump|else|encode|exists|explain|false|field|float|floor|for|format|from|group|having|hex|if|ifnull|in|index|information_schema|insert|int|into|is|join|key|kill|left|length|like|limit|load|long|lower|ltrim|match|max|md5|mid|min|mod|name|not|null|or|ord|order|procedure|replace|reverse|right|row|rtrim|schema|select|separator|sha|sleep|smallint|space|substr|substring|sum|table|then|to|trim|true|type|unhex|union|update|upper|using|value|values|version|when|where|xor)`,
	},

	// Category D: anchor/separator + keyword (main: nil; ours: anyRequired propagation)
	{
		"D_anchor_xss",
		`(?i)(?:^|["':;=])\s*(?:alert|prompt|confirm|eval|onerror|onload|onclick)`,
	},
	{
		"D_anchor_sqli",
		`(?i)(?:^|["':;=\s])\s*(?:select|union|insert|update|delete|drop|exec)`,
	},

	// Category E: no extractable literal – neither branch prefilters
	{
		"E_no_prefilter_charclass",
		`(?:[a-z0-9]{2,}\.[a-z]{2,3}(?:\.[a-z]{2})?(?:/[\w\-]+)*)`,
	},
	{
		"E_no_prefilter_wildcard",
		`(?:\b\w+\b[\s\S]*?\b\w+\b[\s\S]*?){3,}`,
	},
}

// ---------------------------------------------------------------------------
// Request payloads grouped by type
// ---------------------------------------------------------------------------

type benchRequest struct {
	name string
	body string
}

var bcRequests = []benchRequest{
	{
		"benign",
		"GET /api/v1/users?page=2&limit=20&sort=created_at HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json",
	},
	{
		"sqli",
		"id=1 UNION SELECT username,password FROM users WHERE 1=1--",
	},
	{
		"xss",
		`search=<script>alert(document.cookie)</script>&safe=off`,
	},
	{
		"cmdi",
		`file=report.pdf&format=pdf; ls -la /etc/passwd`,
	},
	{
		"path",
		`file=../../../../../../../etc/passwd&base=/var/www/html`,
	},
}

// ---------------------------------------------------------------------------
// BenchmarkCompare/Category_RequestType — prefilter vs regex-only
// ---------------------------------------------------------------------------

func BenchmarkCompare(b *testing.B) {
	for _, pat := range bcPatterns {
		pat := pat
		re := regexp.MustCompile(pat.pattern)
		pf := prefilterFunc(pat.pattern)
		hasPF := pf != nil
		if !hasPF {
			pf = func(string) bool { return true } // always pass through when no prefilter
		}

		for _, req := range bcRequests {
			req := req
			name := pat.name + "/" + req.name

			// regex-only: always run the full regex
			b.Run("regex_only/"+name, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(req.body)))
				for i := 0; i < b.N; i++ {
					_ = re.MatchString(req.body)
				}
			})

			// prefilter+regex: our path (skip regex when prefilter rejects)
			b.Run("prefilter/"+name, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(req.body)))
				for i := 0; i < b.N; i++ {
					if pf(req.body) {
						_ = re.MatchString(req.body)
					}
				}
			})
		}

		// Log whether this pattern has a prefilter on this branch
		b.Log(pat.name, "→ prefilter:", hasPF)
	}
}

