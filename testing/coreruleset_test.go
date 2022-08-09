//go:build !tinygo
// +build !tinygo

// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testing

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/seclang"
	"github.com/corazawaf/coraza/v3/testing/profile"
	"gopkg.in/yaml.v3"
)

var crspath = ""

func init() {
	fmt.Println("Preparing CRS...")
	crs, err := downloadCRS("32e6d80419d386a330ddaf5e60047a4a1c38a160")
	if err != nil {
		panic(err)
	}
	crspath, err = os.MkdirTemp(os.TempDir(), "crs")
	if err != nil {
		panic(err)
	}
	fmt.Println("CRS PATH: " + crspath)
	err = unzip(crs, crspath)
	if err != nil {
		panic(err)
	}
	prepareAdvancedTests()
}

func BenchmarkCRSCompilation(b *testing.B) {
	files := []string{
		"../coraza.conf-recommended",
		path.Join(crspath, "crs-setup.conf.example"),
		path.Join(crspath, "rules/", "*.conf"),
	}
	for i := 0; i < b.N; i++ {
		waf := coraza.NewWaf()
		parser, _ := seclang.NewParser(waf)
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
	waf, err := crsWAF()
	if err != nil {
		b.Error(err)
	}
	for i := 0; i < b.N; i++ {
		tx := waf.NewTransaction(context.Background())
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
		if err := tx.Clean(); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkCRSSimplePOST(b *testing.B) {
	waf, err := crsWAF()
	if err != nil {
		b.Error(err)
	}
	for i := 0; i < b.N; i++ {
		tx := waf.NewTransaction(context.Background())
		tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 8080)
		tx.ProcessURI("POST", "/some_path/with?parameters=and&other=Stuff", "HTTP/1.1")
		tx.AddRequestHeader("Host", "localhost")
		tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36")
		tx.AddRequestHeader("Accept", "application/json")
		tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
		tx.ProcessRequestHeaders()
		if _, err := tx.RequestBodyBuffer.Write([]byte("parameters2=and&other2=Stuff")); err != nil {
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
		if err := tx.Clean(); err != nil {
			b.Error(err)
		}
	}
}

func crsWAF() (*coraza.Waf, error) {
	files := []string{
		"../coraza.conf-recommended",
		path.Join(crspath, "crs-setup.conf.example"),
		path.Join(crspath, "rules/", "*.conf"),
	}
	waf := coraza.NewWaf()
	parser, _ := seclang.NewParser(waf)
	for _, f := range files {
		if err := parser.FromFile(f); err != nil {
			return nil, err
		}
	}
	return waf, nil
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
	tmpfile, err := ioutil.TempFile(os.TempDir(), "crs")
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

func unzip(file string, dst string) error {
	archive, err := zip.OpenReader(file)
	if err != nil {
		panic(err)
	}
	defer archive.Close()

	for i, f := range archive.File {
		// we strip the first directory from f.Name
		filePath := filepath.Join(dst, f.Name)
		if i == 0 {
			// get file basename
			crspath = path.Join(crspath, filepath.Base(filePath))
		}

		if !strings.HasPrefix(filePath, filepath.Clean(dst)+string(os.PathSeparator)) {
			return fmt.Errorf("%s: illegal file path", filePath)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
				return err
			}
			continue
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
	}
	return nil
}

func prepareAdvancedTests() {
	// wait until
	waf := coraza.NewWaf()
	parser, _ := seclang.NewParser(waf)
	if err := parser.FromString(`SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.combined_file_sizes=65535"`); err != nil {
		panic(err)
	}
	files := []string{
		"../coraza.conf-recommended",
		path.Join(crspath, "crs-setup.conf.example"),
		path.Join(crspath, "rules/", "*.conf"),
	}
	for _, f := range files {
		if err := parser.FromFile(f); err != nil {
			panic(err)
		}
	}
	files = []string{}
	// we search for all .yaml files in crspath/tests/regression/tests/
	if err := filepath.Walk(crspath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".yaml") {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		panic(err)
	}
	fmt.Printf("Got %d CRS test files\n", len(files))
	for _, f := range files {
		// we read the yaml files and parse them as profile.Profile
		content, err := os.ReadFile(f)
		if err != nil {
			panic(err)
		}
		var pf *profile.Profile
		if err := yaml.Unmarshal(content, &pf); err != nil {
			panic(err)
		}
		profile.RegisterProfile(*pf)
	}
}
