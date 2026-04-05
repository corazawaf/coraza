//go:build coraza.rule.rx_prefilter

// bench_compare_test.go: apples-to-apples benchmark across branch and main.
//
// Covers four regex categories and four request types so we can clearly show
// where each optimisation helps:
//
//	Category A – simple literal  (main already prefilters, baseline control)
//	Category B – small alternation ≤16 needles (main: AC; ours: Wu-Manber)
//	Category C – large trie alternation (main: no prefilter; ours: trie-reconstruct)
//	Category D – anchor/separator + keyword (main: no prefilter; ours: anyRequired propagation)
//	Category E – zero-extractable-literal (no prefilter on either branch)
//
//	Request types:
//	  benign   – normal HTTP traffic that should never match
//	  sqli     – classic SQL injection
//	  xss      – XSS payload
//	  cmdi     – command injection
//	  path     – path traversal
//
// Run on both branches and compare with benchstat:
//
//	go test -tags coraza.rule.rx_prefilter -bench BenchmarkCompare \
//	    -benchmem -benchtime=4s -count=6 | tee /tmp/branch.txt
//	  (switch to main)
//	go test -tags coraza.rule.rx_prefilter -bench BenchmarkCompare \
//	    -benchmem -benchtime=4s -count=6 | tee /tmp/main.txt
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
	// benign
	{
		"benign_get",
		"GET /api/v1/users?page=2&limit=20&sort=created_at HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature",
	},
	{
		"benign_post_json",
		`POST /api/orders HTTP/1.1\r\nHost: shop.example.com\r\nContent-Type: application/json\r\n\r\n{"user_id":42,"items":[{"sku":"ABC-123","qty":2},{"sku":"XYZ-999","qty":1}],"promo":"SUMMER20"}`,
	},
	{
		"benign_form_post",
		"username=alice&password=hunter2&remember=true&redirect=%2Fdashboard&csrf_token=a1b2c3d4e5f6",
	},
	{
		"benign_search",
		"q=golang+performance+benchmarks+2024&page=1&safe=on&hl=en",
	},

	// SQL injection
	{
		"sqli_union",
		"id=1 UNION SELECT username,password,3,4,5 FROM users WHERE 1=1--",
	},
	{
		"sqli_tautology",
		"username=admin'--&password=anything' OR '1'='1",
	},
	{
		"sqli_blind",
		"id=1 AND SLEEP(5)-- &page=1",
	},
	{
		"sqli_stacked",
		"name=test'; DROP TABLE users; SELECT * FROM secrets WHERE 'a'='a",
	},

	// XSS
	{
		"xss_script_tag",
		`search=<script>alert(document.cookie)</script>&safe=off`,
	},
	{
		"xss_event_attr",
		`name="><img src=x onerror=alert(1)>&comment=normal text`,
	},
	{
		"xss_js_uri",
		`url=javascript:eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))`,
	},
	{
		"xss_anchor_alert",
		`input=";alert(document.domain)//`,
	},

	// Command injection
	{
		"cmdi_pipe",
		`file=report.pdf&format=pdf; ls -la /etc/passwd`,
	},
	{
		"cmdi_subshell",
		`host=example.com$(cat /etc/shadow)&port=80`,
	},

	// Path traversal
	{
		"path_traversal",
		`file=../../../../../../../etc/passwd&base=/var/www/html`,
	},
	{
		"path_encoded",
		`path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow&action=read`,
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

// ---------------------------------------------------------------------------
// BenchmarkCompareSummary — one number per category (all request types mixed)
// ---------------------------------------------------------------------------

func BenchmarkCompareSummary(b *testing.B) {
	// Pre-compile everything
	type compiled struct {
		pat benchPattern
		re  *regexp.Regexp
		pf  func(string) bool
	}
	entries := make([]compiled, 0, len(bcPatterns))
	for _, pat := range bcPatterns {
		pf := prefilterFunc(pat.pattern)
		if pf == nil {
			pf = func(string) bool { return true }
		}
		entries = append(entries, compiled{
			pat: pat,
			re:  regexp.MustCompile(pat.pattern),
			pf:  pf,
		})
	}

	for _, e := range entries {
		e := e
		b.Run("regex_only/"+e.pat.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, req := range bcRequests {
					_ = e.re.MatchString(req.body)
				}
			}
		})
		b.Run("prefilter/"+e.pat.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, req := range bcRequests {
					if e.pf(req.body) {
						_ = e.re.MatchString(req.body)
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BenchmarkPrefilterOnly — isolates cost of the prefilter check itself
// ---------------------------------------------------------------------------

func BenchmarkPrefilterOnly(b *testing.B) {
	for _, pat := range bcPatterns {
		pat := pat
		pf := prefilterFunc(pat.pattern)
		if pf == nil {
			continue // nothing to benchmark
		}
		for _, req := range bcRequests {
			req := req
			b.Run(pat.name+"/"+req.name, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(req.body)))
				for i := 0; i < b.N; i++ {
					_ = pf(req.body)
				}
			})
		}
	}
}
