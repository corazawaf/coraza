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

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package seclang

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
)

// from issue https://github.com/corazawaf/coraza/issues/159 @zpeasystart
func TestDirectiveSecAuditLog(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
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
	macro, err := coraza.NewMacro("%{tx.count}")
	if err != nil {
		t.Error(err)
	}
	c, _ = strconv.Atoi(macro.Expand(tx))
	if c != 6 {
		t.Errorf("Why is the number of matches %d", c)
	}
}
