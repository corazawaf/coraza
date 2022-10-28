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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/runner"
	"github.com/coreruleset/go-ftw/test"
	"github.com/rs/zerolog"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/seclang"
	"github.com/corazawaf/coraza/v3/types"
)

var crspath string

func init() {
	fmt.Println("Preparing CRS...")
	crs, err := downloadCRS("32e6d80419d386a330ddaf5e60047a4a1c38a160")
	if err != nil {
		panic(fmt.Sprintf("failed to download CRS: %s", err.Error()))
	}
	tmpPath, err := os.MkdirTemp(os.TempDir(), "crs")
	if err != nil {
		panic(fmt.Sprintf("failed to create temp folder for CRS: %s", err.Error()))
	}
	fmt.Println("CRS PATH: " + tmpPath)
	crspath, err = unzip(crs, tmpPath)
	if err != nil {
		panic(fmt.Sprintf("failed to unzip CRS: %s", err.Error()))
	}
}

func BenchmarkCRSCompilation(b *testing.B) {
	files := []string{
		filepath.Join("..", "..", "coraza.conf-recommended"),
		filepath.Join(crspath, "crs-setup.conf.example"),
		filepath.Join(crspath, "rules", "*.conf"),
	}
	for i := 0; i < b.N; i++ {
		waf := corazawaf.NewWAF()
		parser := seclang.NewParser(waf)
		for _, f := range files {
			if err := parser.FromFile(f); err != nil {
				b.Error(err)
			}
		}
		if waf.Rules.Count() < 500 {
			b.Error("Not enough rules")
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
	// Configs are loaded with a precise order:
	// 1. Coraza config
	// 2. Custom Rules for testing and eventually overrides of the basic Coraza config
	// 3. CRS basic config
	// 4. CRS rules (on top of which are applied the previously defined SecDefaultAction)
	conf = conf.WithDirectivesFromFile(filepath.Join("..", "..", "coraza.conf-recommended"))
	conf = conf.WithDirectives(`
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
`)
	conf = conf.WithDirectivesFromFile(filepath.Join(crspath, "crs-setup.conf.example"))
	conf = conf.WithDirectivesFromFile(filepath.Join(crspath, "rules", "*.conf"))

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
		// Emulated http behaviour: /anything endpoint acts as an echo server, writing back the request body
		if r.URL.Path == "/anything" {
			var buf bytes.Buffer
			_, err = io.Copy(&buf, r.Body)
			if err != nil {
				t.Fatalf("handler can not read request body: %v", err)
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Write(buf.Bytes())
		} else {
			fmt.Fprintf(w, "Hello!")
		}
	})))
	defer s.Close()

	tests, err := test.GetTestsFromFiles(filepath.Join(crspath, "tests", "regression", "tests", "**", "*.yaml"))
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
	files := []string{
		filepath.Join("..", "..", "coraza.conf-recommended"),
		filepath.Join(crspath, "crs-setup.conf.example"),
		filepath.Join(crspath, "rules", "*.conf"),
	}
	conf := coraza.NewWAFConfig()

	for _, f := range files {
		conf = conf.WithDirectivesFromFile(f)
	}

	waf, err := coraza.NewWAF(conf)
	if err != nil {
		t.Fatal(err)
	}

	return waf
}
func downloadCRS(version string) (string, error) {
	uri := fmt.Sprintf("https://github.com/coreruleset/coreruleset/archive/%s.zip", version)
	// download file from uri
	res, err := http.Get(uri)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	// create tmp file
	tmpfile, err := os.CreateTemp(os.TempDir(), "crs")
	if err != nil {
		return "", err
	}
	// write file to tmp file
	_, err = io.Copy(tmpfile, res.Body)
	if err != nil {
		return "", err
	}
	return tmpfile.Name(), nil
}

func unzip(file string, dst string) (string, error) {
	archive, err := zip.OpenReader(file)
	if err != nil {
		panic(err)
	}
	defer archive.Close()

	crspath = dst
	for i, f := range archive.File {
		// we strip the first directory from f.Name
		filePath := filepath.Join(dst, f.Name)
		if i == 0 {
			// get file basename
			crspath = filepath.Join(dst, filepath.Base(filePath))
		}

		if !strings.HasPrefix(filePath, filepath.Clean(dst)+string(os.PathSeparator)) {
			return "", fmt.Errorf("%s: illegal file path", filePath)
		}

		if err := unzipFile(filePath, f); err != nil {
			return "", err
		}
	}
	return crspath, nil
}

func unzipFile(filePath string, f *zip.File) error {
	if f.FileInfo().IsDir() {
		if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
			return err
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return err
	}

	dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	fileInArchive, err := f.Open()
	if err != nil {
		return err
	}
	defer fileInArchive.Close()

	if _, err := io.Copy(dstFile, fileInArchive); err != nil {
		return err
	}

	return nil
}
