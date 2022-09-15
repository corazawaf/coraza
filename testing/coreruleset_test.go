// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// These benchmarks don't currently compile with TinyGo
//go:build !tinygo
// +build !tinygo

package testing

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/seclang"
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
		"../coraza.conf-recommended",
		path.Join(crspath, "crs-setup.conf.example"),
		path.Join(crspath, "rules/", "*.conf"),
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
	waf := crsWAF(b)

	b.ResetTimer() // only benchmark execution, not compilation
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

func crsWAF(t testing.TB) *corazawaf.WAF {
	t.Helper()
	files := []string{
		"../coraza.conf-recommended",
		path.Join(crspath, "crs-setup.conf.example"),
		path.Join(crspath, "rules/", "*.conf"),
	}
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	for _, f := range files {
		if err := parser.FromFile(f); err != nil {
			t.Fatal(err)
		}
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
			crspath = path.Join(dst, filepath.Base(filePath))
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
