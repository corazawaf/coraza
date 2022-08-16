// tinygo does not support net.http so this package is not needed for it
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

package http

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestRequestExtractionSuccess(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://www.coraza.io/test", strings.NewReader("test=456"))
	waf := coraza.NewWaf()
	tx := waf.NewTransaction(context.Background())
	if _, err := ProcessRequest(tx, req); err != nil {
		t.Fatal(err)
	}
	if tx.Variables.RequestMethod.String() != "POST" {
		t.Fatal("failed to set request from request object")
	}
	if err := tx.Clean(); err != nil {
		t.Fatal(err)
	}
}

func TestProcessRequestMultipart(t *testing.T) {
	req, _ := http.NewRequest("POST", "/some", nil)
	if err := multipartRequest(t, req); err != nil {
		t.Fatal(err)
	}
	tx := makeTransaction(t)
	tx.RequestBodyAccess = true
	if _, err := ProcessRequest(tx, req); err != nil {
		t.Fatal(err)
	}
	if req.Body == nil {
		t.Error("failed to process multipart request")
	}
	reader := bufio.NewReader(req.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Error("failed to read multipart request", err)
	}
	if err := tx.Clean(); err != nil {
		t.Error(err)
	}
}

func multipartRequest(t *testing.T, req *http.Request) error {
	t.Helper()

	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	tempfile, err := os.Create(filepath.Join(t.TempDir(), "tmpfile"))
	if err != nil {
		return err
	}
	for i := 0; i < 1024*5; i++ {
		// this should create a 5mb file
		if _, err := tempfile.Write([]byte(strings.Repeat("A", 1024))); err != nil {
			return err
		}
	}
	var fw io.Writer
	if fw, err = w.CreateFormFile("fupload", tempfile.Name()); err != nil {
		return err
	}
	if _, err := tempfile.Seek(0, 0); err != nil {
		return err
	}
	if _, err = io.Copy(fw, tempfile); err != nil {
		return err
	}
	req.Body = ioutil.NopCloser(&b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Method = "POST"
	return nil
}

func makeTransaction(t *testing.T) *coraza.Transaction {
	t.Helper()
	tx := coraza.NewWaf().NewTransaction(context.Background())
	tx.RequestBodyAccess = true
	ht := []string{
		"POST /testurl.php?id=123&b=456 HTTP/1.1",
		"Host: www.test.com:80",
		"Cookie: test=123",
		"Content-Type: application/x-www-form-urlencoded",
		"X-Test-Header: test456",
		"Content-Length: 13",
		"",
		"testfield=456",
	}
	data := strings.Join(ht, "\r\n")
	_, _ = tx.ParseRequestReader(strings.NewReader(data))
	return tx
}
