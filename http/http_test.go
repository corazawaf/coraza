// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package http

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/seclang"
	"github.com/corazawaf/coraza/v3/macro"
)

func TestProcessRequest(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://www.coraza.io/test", strings.NewReader("test=456"))
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction(context.Background())
	if _, err := processRequest(tx, req); err != nil {
		t.Fatal(err)
	}
	if tx.Variables.RequestMethod.String() != "POST" {
		t.Fatal("failed to set request from request object")
	}
	if err := tx.Close(); err != nil {
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
	if _, err := processRequest(tx, req); err != nil {
		t.Fatal(err)
	}
	if req.Body == nil {
		t.Error("failed to process multipart request")
	}
	defer req.Body.Close()

	reader := bufio.NewReader(req.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Error("failed to read multipart request", err)
	}
	if err := tx.Close(); err != nil {
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
	req.Body = io.NopCloser(&b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Method = "POST"
	return nil
}

func makeTransaction(t *testing.T) *corazawaf.Transaction {
	t.Helper()
	tx := corazawaf.NewWAF().NewTransaction(context.Background())
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

// from issue https://github.com/corazawaf/coraza/issues/159 @zpeasystart
func TestDirectiveSecAuditLog(t *testing.T) {
	waf := corazawaf.NewWAF()
	p := seclang.NewParser(waf)
	if err := p.FromString(`
	SecRule REQUEST_FILENAME "@unconditionalMatch" "id:100, phase:2, t:none, log, setvar:'tx.count=+1',chain"
	SecRule ARGS:username "@unconditionalMatch" "t:none, setvar:'tx.count=+2',chain"
	SecRule ARGS:password "@unconditionalMatch" "t:none, setvar:'tx.count=+3'"
		`); err != nil {
		t.Error(err)
	}
	tx := waf.NewTransaction(context.Background())
	tx.RequestBodyAccess = true
	tx.ForceRequestBodyVariable = true
	// request
	rdata := []string{
		"POST /login HTTP/1.1",
		"Accept: */*",
		"Accept-Encoding: gzip, deflate",
		"Connection: close",
		"Origin: http://test.com",
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
		"Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
		"Referer: http://somehost.com/login.jsp",
		"X-Requested-With: XMLHttpRequest",
		"Content-Length: 59",
		"Accept-Language: zh-CN,zh;q=0.9",
		"",
		"username=root&password=123&rememberMe=on&time=1644979180757",
	}
	data := bytes.NewBuffer([]byte(strings.Join(rdata, "\r\n")))
	req, err := http.ReadRequest(bufio.NewReader(data))
	if err != nil {
		t.Errorf("Description HTTP request parsing failed")
	}

	_, err = processRequest(tx, req)
	if err != nil {
		t.Errorf("Failed to load the HTTP request")
	}

	rulesCounter := 0
	r := waf.Rules.FindByID(100)
	for r != nil {
		rulesCounter++
		r = r.Chain
	}
	if want, have := 3, rulesCounter; want != have {
		t.Errorf("failed to compile multiple chains, want: %d, have: %d", want, have)
	}

	m, err := macro.NewMacro("%{tx.count}")
	if err != nil {
		t.Fatalf("failed to initialize the macro: %v", err)
	}

	txCount, _ := strconv.Atoi(m.Expand(tx))
	if want, have := 6, txCount; want != have {
		t.Errorf("incorrect counter, want %d, have %d", want, have)
	}
}
