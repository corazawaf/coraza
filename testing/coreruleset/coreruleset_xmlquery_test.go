// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// These benchmarks don't currently compile with TinyGo
//go:build !tinygo

package coreruleset

import (
	"bufio"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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

	// Register the experimental xmlquery body processor so that
	// ctl:requestBodyProcessor=XMLQUERY is available.
	_ "github.com/corazawaf/coraza/v3/experimental/plugins"
)

// TestFTWXMLQuery runs the full CRS FTW test suite using the experimental
// xmlquery body processor instead of the default XML processor.
// This verifies that the lazy XPath-backed collection is fully compatible
// with CRS rules that inspect XML request bodies.
func TestFTWXMLQuery(t *testing.T) {
	conf := coraza.NewWAFConfig()

	rec, err := os.ReadFile(filepath.Join("..", "..", "coraza.conf-recommended"))
	if err != nil {
		t.Fatal(err)
	}

	// Override rule 200000 to use the experimental xmlquery processor.
	// SecRuleUpdateActionById replaces the action list for the existing rule,
	// switching from requestBodyProcessor=XML to requestBodyProcessor=XMLQUERY.
	xmlqueryOverride := `
SecRuleUpdateActionById 200000 "phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XMLQUERY"
`

	customTestingConfig := `
SecResponseBodyMimeType text/plain
SecDefaultAction "phase:3,log,auditlog,pass"
SecDefaultAction "phase:4,log,auditlog,pass"
SecDefaultAction "phase:5,log,auditlog,pass"

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
	conf = conf.
		WithRootFS(coreruleset.FS).
		WithDirectives(string(rec)).
		WithDirectives(customTestingConfig).
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives("Include @owasp_crs/*.conf").
		WithDirectives(xmlqueryOverride)

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

	s := httptest.NewServer(txhttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
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
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	cfg, err := config.NewConfigFromFile(".ftw.yml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.LogFile = errorPath
	cfg.TestOverride.Overrides.DestAddr = &host
	cfg.TestOverride.Overrides.Port = &port

	if err := loadMultiphaseOverrides(cfg); err != nil {
		t.Fatal(err)
	}
	runnerCfg := config.NewRunnerConfiguration(cfg)
	runnerCfg.ReadTimeout = 3 * time.Second
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
