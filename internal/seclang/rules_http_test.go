// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package seclang

import (
	"bufio"
	"bytes"
	"context"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"net/http"
	"strconv"
	"strings"
	"testing"

	txhttp "github.com/corazawaf/coraza/v3/http"
)

// from issue https://github.com/corazawaf/coraza/issues/159 @zpeasystart
func TestDirectiveSecAuditLog(t *testing.T) {
	waf := corazawaf.NewWAF()
	p := NewParser(waf)
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
	_, err = txhttp.ProcessRequest(tx, req)
	if err != nil {
		t.Errorf("Failed to load the HTTP request")
	}
	// There is no problem loading the rules
	c := 0
	r := waf.Rules.FindByID(100)
	for r != nil {
		c++
		r = r.Chain
	}
	if c != 3 {
		t.Errorf("failed to compile multiple chains, expected 3, got %d", c)
	}
	// Why is the number of matches 4
	macro, err := corazawaf.NewMacro("%{tx.count}")
	if err != nil {
		t.Error(err)
	}
	c, _ = strconv.Atoi(macro.Expand(tx))
	if c != 6 {
		t.Errorf("Why is the number of matches %d", c)
	}
}
