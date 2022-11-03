// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// These benchmarks don't currently compile with TinyGo
//go:build !tinygo
// +build !tinygo

package coreruleset

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/runner"
	"github.com/coreruleset/go-ftw/test"
	"github.com/rs/zerolog"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

var crsReader fs.FS

func init() {
	fmt.Println("Preparing CRS...")
	ver := "32e6d80419d386a330ddaf5e60047a4a1c38a160"
	if crs, err := downloadCRS(ver); err != nil {
		panic(fmt.Sprintf("failed to download CRS: %s", err.Error()))
	} else {
		if f, err := fs.Sub(crs, fmt.Sprintf("coreruleset-%s", ver)); err != nil {
			panic(err)
		} else {
			crsReader = f
		}
	}
}

func BenchmarkCRSCompilation(b *testing.B) {
	rec, err := os.ReadFile(filepath.Join("..", "..", "coraza.conf-recommended"))
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		_, err := coraza.NewWAF(coraza.NewWAFConfig().
			WithRootFS(crsReader).
			WithDirectives(string(rec)).
			WithDirectives("Include crs-setup.conf.example").
			WithDirectives("Include rules/*.conf"))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCRSSimpleGET(b *testing.B) {
	waf := crsWAF(b)

	b.ResetTimer() // only benchmark execution, not compilation
	for i := 0; i < b.N; i++ {
		tx := waf.NewTransaction()
		tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 8080)
		tx.ProcessURI("GET", "/some_path/with?parameters=and&other=Stuff", "HTTP/1.1")
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

	b.ResetTimer() // only benchmark execution, not compilation
	for i := 0; i < b.N; i++ {
		tx := waf.NewTransaction()
		tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 8080)
		tx.ProcessURI("POST", "/some_path/with?parameters=and&other=Stuff", "HTTP/1.1")
		tx.AddRequestHeader("Host", "localhost")
		tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36")
		tx.AddRequestHeader("Accept", "application/json")
		tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
		tx.ProcessRequestHeaders()
		if _, err := tx.ResponseBodyWriter().Write([]byte("parameters2=and&other2=Stuff")); err != nil {
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

func TestFTW(t *testing.T) {
	conf := coraza.NewWAFConfig()

	rec, err := os.ReadFile(filepath.Join("..", "..", "coraza.conf-recommended"))
	if err != nil {
		t.Fatal(err)
	}

	customTestingConfig := `
SecResponseBodyMimeType text/plain
SecDefaultAction "phase:3,log,auditlog,pass"
SecDefaultAction "phase:4,log,auditlog,pass"

SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  # Interferes with ftw log scanning
  ctl:ruleRemoveById=920250,\
  setvar:tx.paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.max_file_size=64100,\
  setvar:tx.combined_file_sizes=65535"

# Write the value from the X-CRS-Test header as a marker to the log
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
  "id:999999,\
  phase:1,\
  log,\
  msg:'X-CRS-Test %{MATCHED_VAR}',\
  pass,\
  t:none"
`
	// Configs are loaded with a precise order:
	// 1. Coraza config
	// 2. Custom Rules for testing and eventually overrides of the basic Coraza config
	// 3. CRS basic config
	// 4. CRS rules (on top of which are applied the previously defined SecDefaultAction)
	conf = conf.
		WithRootFS(crsReader).
		WithDirectives(string(rec)).
		WithDirectives(customTestingConfig).
		WithDirectives("Include crs-setup.conf.example").
		WithDirectives("Include rules/*.conf")

	errorPath := filepath.Join(t.TempDir(), "error.log")
	errorFile, err := os.Create(errorPath)
	if err != nil {
		t.Fatalf("failed to create error log: %v", err)
	}
	errorWriter := bufio.NewWriter(errorFile)
	conf = conf.WithErrorLogger(func(rule types.MatchedRule) {
		msg := rule.ErrorLog(0)
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

	s := httptest.NewServer(txhttp.WrapHandler(waf, t.Logf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Emulated httpbin behaviour: /anything endpoint acts as an echo server, writing back the request body
		if r.URL.Path == "/anything" {
			defer r.Body.Close()
			w.Header().Set("Content-Type", "text/plain")
			_, err = io.Copy(w, r.Body)
			if err != nil {
				t.Fatalf("handler can not read request body: %v", err)
			}
		} else {
			fmt.Fprintf(w, "Hello!")
		}
	})))
	defer s.Close()

	var tests []test.FTWTest
	err = doublestar.GlobWalk(crsReader, "tests/regression/tests/**/*.yaml", func(path string, d os.DirEntry) error {
		yaml, err := fs.ReadFile(crsReader, path)
		if err != nil {
			return err
		}
		t, err := test.GetTestFromYaml(yaml)
		if err != nil {
			return err
		}
		tests = append(tests, t)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	u, _ := url.Parse(s.URL)
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	// TODO(anuraaga): Don't use global config for FTW for better support of programmatic.
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	_ = config.NewConfigFromFile(".ftw.yml")
	config.FTWConfig.LogFile = errorPath
	config.FTWConfig.TestOverride.Input.DestAddr = &host
	config.FTWConfig.TestOverride.Input.Port = &port

	res := runner.Run(tests, runner.Config{
		ShowTime: false,
		Quiet:    true,
	})

	if len(res.Stats.Failed) > 0 {
		t.Errorf("failed tests: %v", res.Stats.Failed)
	}
}

func crsWAF(t testing.TB) coraza.WAF {
	t.Helper()
	rec, err := os.ReadFile(filepath.Join("..", "..", "coraza.conf-recommended"))
	if err != nil {
		t.Fatal(err)
	}
	conf := coraza.NewWAFConfig().
		WithDirectives(string(rec)).
		WithDirectives("Include crs-setup.conf.example").
		WithDirectives("Include rules/*.conf")

	waf, err := coraza.NewWAF(conf)
	if err != nil {
		t.Fatal(err)
	}

	return waf
}
func downloadCRS(version string) (*zip.Reader, error) {
	uri := fmt.Sprintf("https://github.com/coreruleset/coreruleset/archive/%s.zip", version)
	// download file from uri
	res, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	crsZip, err := io.ReadAll(res.Body)
	return zip.NewReader(bytes.NewReader(crsZip), int64(len(crsZip)))
}
