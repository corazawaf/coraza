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

package seclang

import (
	"bufio"
	"bytes"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types/variables"
)

func TestRuleMatch(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On
		SecDefaultAction "phase:1,deny,status:403,log"
		SecRule REMOTE_ADDR "^127.*" "id:1,phase:1"
		SecRule REMOTE_ADDR "!@rx 127.0.0.1" "id:2,phase:1"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.ProcessConnection("127.0.0.1", 0, "", 0)
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules) != 1 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules))
	}
	if tx.Interruption == nil {
		t.Error("failed to interrupt transaction")
	}

	if tx.Interruption.RuleID != 1 {
		t.Error("failed to set interruption rule id")
	}
}

func TestRuleMatchWithRegex(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On
		SecDefaultAction "phase:1,deny,status:403,log"
		SecRule ARGS:/^id_.*/ "123" "phase:1, id:1"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "id_test", "123")
	tx.ProcessRequestHeaders()
	if tx.GetCollection(variables.Args).GetFirstString("id_test") != "123" {
		t.Error("rule variable error")
	}
	if len(tx.MatchedRules) != 1 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules))
	}
	if tx.Interruption == nil {
		t.Error("failed to interrupt transaction")
	} else if tx.Interruption.RuleID != 1 {
		t.Error("failed to set interruption rule id")
	}
}

func TestSecMarkers(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On		
		SecAction "phase:1, id:1,log,skipAfter:SoMe_TEST"
		SecAction "phase:1, id:2,deny,status:403"

		SecMarker SoMe_TEST
		SecAction "phase:2, id:3,deny,status:403,log"
	`)

	if err != nil {
		t.Error(err.Error())
	}

	if waf.Rules.Count() != 4 {
		t.Error("failed to compile some rule.")
	}

	tx := waf.NewTransaction()
	defer tx.ProcessLogging()
	tx.ProcessRequestHeaders()
	if tx.Interrupted() {
		t.Error("transaction failed to skipAfter")
	}
	interruption, err := tx.ProcessRequestBody()
	if interruption == nil || err != nil {
		t.Error("failed to interrupt")
	}
	if len(tx.MatchedRules) == 1 {
		t.Errorf("not matching any rule after secmark")
	}
}

func TestSecAuditLogs(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecAuditEngine On
		SecAction "id:4482,log,auditlog, msg:'test'"
		SecAuditLogParts ABCDEFGHIJK
		SecRuleEngine On
	`)
	if err != nil {
		t.Error(err)
	}
	tx := waf.NewTransaction()
	tx.ProcessURI("/test.php?id=1", "get", "http/1.1")
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Error(err)
	}
	tx.ProcessLogging()

	if len(tx.MatchedRules) == 0 {
		t.Error("failed to match rules")
	}

	if tx.AuditLog().Messages[0].Data.ID != 4482 {
		t.Error("failed to match rule id")
	}
}

func TestRuleLogging(t *testing.T) {
	waf := coraza.NewWaf()
	logs := []string{}
	waf.SetErrorLogCb(func(mr coraza.MatchedRule) {
		logs = append(logs, mr.ErrorLog(403))
	})
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS ".*" "phase:1, id:1,capture,log,setvar:'tx.arg_%{tx.0}=%{tx.0}'"
		SecAction "id:2,phase:1,log,setvar:'tx.test=ok'"
		SecAction "id:3,phase:1,nolog"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules) != 3 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules))
	}
	// we expect 2 logs
	if len(logs) != 2 {
		t.Errorf("failed to log with %d", len(logs))
	} else {
		for _, l := range logs[:1] {
			if !strings.Contains(l, "[id \"1\"]") {
				t.Errorf("failed to log rule, got \n%s", l)
			}
		}
		if !strings.Contains(logs[1], "[id \"2\"]") {
			t.Errorf("failed to log rule, got \n%s", logs[2])
		}
	}
	txcol := tx.GetCollection(variables.TX)
	if txcol.GetFirstString("arg_123") != "123" || txcol.GetFirstString("arg_456") != "456" {
		t.Errorf("failed to match setvar from multiple match, got %q and %q", txcol.GetFirstString("arg_test1"), txcol.GetFirstString("arg_test2"))
	}
	if txcol.GetFirstString("test") != "ok" {
		t.Errorf("failed to match setvar from multiple match, got %q", txcol.GetFirstString("test"))
	}
}

func TestRuleChains(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS "123" "id:1,phase:1,log,chain"
			SecRule &ARGS "@gt 0" "chain"
			SecRule ARGS "456" "setvar:'tx.test=ok'"
		
		SecRule ARGS "123" "id:2,phase:1,log,chain"
			SecRule &ARGS "@gt 100" "chain"
			SecRule ARGS "456" "setvar:'tx.test2=fail'"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules) != 1 {
		t.Errorf("failed to match rules with %d matches, expected 1", len(tx.MatchedRules))
	}
	if tx.GetCollection(variables.TX).GetFirstString("test") != "ok" {
		t.Error("failed to set var")
	}
	if tx.GetCollection(variables.TX).GetFirstString("test2") == "fail" {
		t.Error("failed to set var, it shouldn't be set")
	}
}

func TestTagsAreNotPrintedTwice(t *testing.T) {
	waf := coraza.NewWaf()
	logs := []string{}
	waf.SetErrorLogCb(func(mr coraza.MatchedRule) {
		logs = append(logs, mr.ErrorLog(403))
	})
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS ".*" "phase:1, id:1,log,tag:'some1',tag:'some2'"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules) != 1 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules))
	}
	// we expect 1 log
	if len(logs) != 1 {
		t.Errorf("failed to log with %d", len(logs))
	}
	re := regexp.MustCompile(`\[tag "some1"\]`)
	for _, l := range logs {
		if len(re.FindAllString(l, -1)) < 2 {
			t.Errorf("failed to log tag, missing instances (%d)\n%s", len(re.FindAllString(l, -1)), l)
		}
	}
}

func TestStatusFromInterruptions(t *testing.T) {
	waf := coraza.NewWaf()
	logs := []string{}
	waf.SetErrorLogCb(func(mr coraza.MatchedRule) {
		logs = append(logs, mr.ErrorLog(403))
	})
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS "123" "phase:1, id:1,log,deny,status:500"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")
	it := tx.ProcessRequestHeaders()
	if it == nil {
		t.Error("failed to interrupt")
	} else if it.Status != 500 {
		t.Errorf("failed to set status, got %d", it.Status)
	}
}

func TestChainWithUnconditionalMatch(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	if err := p.FromString(`
	SecAction "id:7, pass, phase:1, log, chain, skip:2"
    SecRule REMOTE_ADDR "@unconditionalMatch" ""
	`); err != nil {
		t.Error(err)
	}
	if waf.Rules.Count() != 1 {
		t.Errorf("invalid rule count, got %d", waf.Rules.Count())
	}
}

func TestLogsAreNotPrintedManyTimes(t *testing.T) {
	waf := coraza.NewWaf()
	logs := []string{}
	waf.SetErrorLogCb(func(mr coraza.MatchedRule) {
		logs = append(logs, mr.ErrorLog(403))
	})
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS|REQUEST_HEADERS|!ARGS:test1 ".*" "phase:1, id:1,log,tag:'some1',tag:'some2'"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")
	tx.AddArgument("GET", "test2", "789")
	tx.AddRequestHeader("test", "123")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules) != 1 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules))
	}
	// we expect 2 logs
	if len(logs) != 1 {
		t.Errorf("failed to log with %d", len(logs))
	}
}

func TestSampleRxRule(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
	SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "phase:1,id:1,log,deny,status:403,chain"
	SecRule REQUEST_HEADERS:Content-Length "!@rx ^0?$"`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.ProcessURI("/test", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Content-Length", "15")
	if it := tx.ProcessRequestHeaders(); it == nil {
		t.Error("failed to interrupt")
	}
}

func TestTXIssue147(t *testing.T) {
	// https://github.com/corazawaf/coraza/issues/147
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`SecRule RESPONSE_BODY "@rx ^#!\s?/" "id:950140,phase:4,log,deny,status:403"`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	// response body access is required
	tx.ResponseBodyAccess = true
	// we need a content-type header
	tx.AddResponseHeader("Content-Type", "text/html")
	if tx.IsProcessableResponseBody() {
		if _, err := tx.ResponseBodyBuffer.Write([]byte("#!/usr/bin/python")); err != nil {
			t.Error(err)
		}
		it, err := tx.ProcessResponseBody()
		if err != nil {
			t.Error(err)
		}
		if it != nil {
			httpOutMsg := ""
			for _, res := range tx.MatchedRules {
				httpOutMsg = httpOutMsg + res.MatchedDatas[0].Key + ":" + res.MatchedDatas[0].Value + "\n"
				httpOutMsg = httpOutMsg + "Message:" + res.MatchedDatas[0].Message + "\n"

			}
			if len(httpOutMsg) == 0 || len(tx.MatchedRules) == 0 {
				t.Error("failed to log")
			}
		} else {
			t.Error("failed to block response body")
		}
	} else {
		t.Error("failed to process response body")
	}
}

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
	tx := waf.NewTransaction()
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
	_, err = tx.ProcessRequest(req)
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

func TestIssue176(t *testing.T) {
	waf := coraza.NewWaf()
	rules := `SecRule REQUEST_COOKIES:sessionId "test" "id:1,phase:1,deny,log,msg:'test rule',logdata:'Matched %{MATCHED_VAR_NAME}'"`
	parser, err := NewParser(waf)
	if err != nil {
		t.Error(err)
		return
	}

	err = parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction()
	tx.AddRequestHeader("Cookie", "sessionId=test")
	it := tx.ProcessRequestHeaders()
	if it == nil {
		t.Error("error test for github issue #176")
	}

	// 	Test for argument case-sensitive
	//	err = parser.FromString(`
	//		SecRule ARGS:Test1 "123" "id:3,phase:1,log,deny"
	//	`)
	//	if err != nil {
	//		t.Error(err.Error())
	//	}
	//	tx = waf.NewTransaction()
	//	tx.AddArgument("GET", "Test1", "123")
	//	it = tx.ProcessRequestHeaders()
	//	if it == nil {
	//		t.Error("failed to test argument case-sensitive")
	//	}
	//
	//	err = parser.FromString(`
	//		SecRule ARGS:test2 "123" "id:5,phase:1,log,deny"
	//	`)
	//	if err != nil {
	//		t.Error(err.Error())
	//	}
	//	tx = waf.NewTransaction()
	//	tx.AddArgument("GET", "Test2", "123")
	//	it = tx.ProcessRequestHeaders()
	//	if it != nil {
	//		t.Error("failed to test argument case-sensitive")
	//	}
}

func TestRxCapture(t *testing.T) {
	waf := coraza.NewWaf()
	rules := `SecRule &TX:allowed_request_content_type_charset "@eq 0" \
        "id:901168,\
        phase:1,\
        pass,\
        nolog,\
        ver:'OWASP_CRS/3.4.0-dev',\
        setvar:'tx.allowed_request_content_type_charset=|utf-8| |iso-8859-1| |iso-8859-15| |windows-1252|'"
    SecRule REQUEST_HEADERS:Content-Type "@rx charset\s*=\s*[\"']?([^;\"'\s]+)" \
        "id:920480,\
        phase:1,\
        deny,\
        capture,\
        t:none,\
        msg:'Request content type charset is not allowed by policy',\
        logdata:'%{MATCHED_VAR}',\
        tag:'application-multi',\
        tag:'language-multi',\
        tag:'platform-multi',\
        tag:'attack-protocol',\
        tag:'paranoia-level/1',\
        tag:'OWASP_CRS',\
        tag:'capec/1000/255/153',\
        tag:'PCI/12.1',\
        ver:'OWASP_CRS/3.4.0-dev',\
        severity:'CRITICAL',\
        setvar:'tx.content_type_charset=|%{tx.1}|',\
        chain"
        SecRule TX:content_type_charset "!@within %{tx.allowed_request_content_type_charset}" \
            "t:lowercase,\
            ctl:forceRequestBodyVariable=On,\
            setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"`
	parser, err := NewParser(waf)
	if err != nil {
		t.Error(err)
		return
	}

	err = parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction()
	tx.AddRequestHeader("Content-Type", "text/html; charset=utf-8")
	it := tx.ProcessRequestHeaders()
	if it != nil {
		t.Error("failed test for rx captured")
	}
}
