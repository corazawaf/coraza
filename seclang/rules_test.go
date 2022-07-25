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
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types/variables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.ProcessConnection("127.0.0.1", 0, "", 0)
	tx.ProcessRequestHeaders()
	require.Len(t, tx.MatchedRules, 1, "failed to match rules")
	require.NotNil(t, tx.Interruption, "failed to interrupt transaction")
	require.Equal(t, 1, tx.Interruption.RuleID, "failed to set interruption rule id")
}

func TestRuleMatchWithRegex(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On
		SecDefaultAction "phase:1,deny,status:403,log"
		SecRule ARGS:/^id_.*/ "123" "phase:1, id:1"
	`)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddArgument("GET", "id_test", "123")
	tx.ProcessRequestHeaders()
	require.Equal(t, "123", tx.GetCollection(variables.Args).GetFirstString("id_test"), "rule variable error")
	require.Len(t, tx.MatchedRules, 1, "failed to match rules")
	require.NotNil(t, tx.Interruption, "failed to interrupt transaction")
	require.Equal(t, 1, tx.Interruption.RuleID, "failed to set interruption rule id")
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
	require.NoError(t, err)

	require.Equal(t, 4, waf.Rules.Count(), "failed to compile some rule.")

	tx := waf.NewTransaction()
	defer tx.ProcessLogging()

	tx.ProcessRequestHeaders()
	require.False(t, tx.Interrupted(), "transaction failed to skipAfter")

	interruption, err := tx.ProcessRequestBody()
	require.NoError(t, err)
	require.NotNil(t, interruption, "failed to interrupt transaction")
	require.NotEqual(t, 1, len(tx.MatchedRules), "not matching any rule after secmark")
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
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.ProcessURI("/test.php?id=1", "get", "http/1.1")
	tx.ProcessRequestHeaders()
	_, err = tx.ProcessRequestBody()
	require.NoError(t, err)

	tx.ProcessLogging()

	require.NotEmpty(t, tx.MatchedRules, "failed to match rules")
	require.Equal(t, 4482, tx.AuditLog().Messages[0].Data.ID, "failed to match rule id")
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
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")
	tx.ProcessRequestHeaders()
	require.Len(t, tx.MatchedRules, 3, "failed to match rules")

	// we expect 2 logs
	require.Len(t, logs, 2, "failed to log")

	for _, l := range logs[:1] {
		assert.Contains(t, l, "[id \"1\"]", "failed to log rule")
	}

	assert.Contains(t, logs[1], "[id \"2\"]", "failed to log rule")

	txcol := tx.GetCollection(variables.TX)
	require.Conditionf(t, func() bool {
		return txcol.GetFirstString("arg_123") == "123" && txcol.GetFirstString("arg_456") == "456"
	}, "failed to match setvar from multiple match, got %q and %q", txcol.GetFirstString("arg_test1"), txcol.GetFirstString("arg_test2"))

	require.Equal(t, "ok", txcol.GetFirstString("test"), "failed to match setvar from multiple match")
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
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")
	tx.ProcessRequestHeaders()
	require.Len(t, tx.MatchedRules, 1, "failed to match rules")

	require.Equal(t, "ok", tx.GetCollection(variables.TX).GetFirstString("test"), "failed to set var")
	require.NotEqual(t, "fail", tx.GetCollection(variables.TX).GetFirstString("test2"), "failed to set var, it shouldn't be set")
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
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")
	tx.ProcessRequestHeaders()
	require.Len(t, tx.MatchedRules, 1, "failed to match rules")

	// we expect 1 log
	require.Len(t, logs, 1, "failed to log")

	re := regexp.MustCompile(`\[tag "some1"\]`)
	for _, l := range logs {
		assert.GreaterOrEqual(t, len(re.FindAllString(l, -1)), 2, "failed to log tag, missing instances")
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
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")

	it := tx.ProcessRequestHeaders()
	require.NotNil(t, it, "failed to interrupt")
	require.Equal(t, 500, it.Status, "failed to set status")
}

func TestChainWithUnconditionalMatch(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)

	err := p.FromString(`
	SecAction "id:7, pass, phase:1, log, chain, skip:2"
    SecRule REMOTE_ADDR "@unconditionalMatch" ""
	`)
	require.NoError(t, err)
	require.Equal(t, 1, waf.Rules.Count(), "invalid rule count")
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
	require.NoError(t, err)
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")
	tx.AddArgument("GET", "test2", "789")
	tx.AddRequestHeader("test", "123")
	tx.ProcessRequestHeaders()
	require.Len(t, tx.MatchedRules, 1, "failed to match rules")
	// we expect 2 logs
	require.Len(t, logs, 1, "failed to log")
}

func TestSampleRxRule(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
	SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "phase:1,id:1,log,deny,status:403,chain"
	SecRule REQUEST_HEADERS:Content-Length "!@rx ^0?$"`)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.ProcessURI("/test", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Content-Length", "15")

	it := tx.ProcessRequestHeaders()
	require.NotNil(t, it, "failed to interrupt")
}

func TestTXIssue147(t *testing.T) {
	// https://github.com/corazawaf/coraza/issues/147
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`SecRule RESPONSE_BODY "@rx ^#!\s?/" "id:950140,phase:4,log,deny,status:403"`)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	// response body access is required
	tx.ResponseBodyAccess = true
	// we need a content-type header
	tx.AddResponseHeader("Content-Type", "text/html")
	require.True(t, tx.IsProcessableResponseBody(), "failed to process response body")

	_, err = tx.ResponseBodyBuffer.Write([]byte("#!/usr/bin/python"))
	require.NoError(t, err)

	it, err := tx.ProcessResponseBody()
	require.NoError(t, err)
	require.NotNil(t, it, "failed to block response body")

	httpOutMsg := ""
	for _, res := range tx.MatchedRules {
		httpOutMsg = httpOutMsg + res.MatchedDatas[0].Key + ":" + res.MatchedDatas[0].Value + "\n"
		httpOutMsg = httpOutMsg + "Message:" + res.MatchedDatas[0].Message + "\n"

	}

	require.NotEmpty(t, httpOutMsg, "failed to log")
	require.NotEmpty(t, tx.MatchedRules, "failed to log")
}

// from issue https://github.com/corazawaf/coraza/issues/159 @zpeasystart
func TestDirectiveSecAuditLog(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	err := p.FromString(`
	SecRule REQUEST_FILENAME "@unconditionalMatch" "id:100, phase:2, t:none, log, setvar:'tx.count=+1',chain"
	SecRule ARGS:username "@unconditionalMatch" "t:none, setvar:'tx.count=+2',chain"
	SecRule ARGS:password "@unconditionalMatch" "t:none, setvar:'tx.count=+3'"
		`)
	require.NoError(t, err)

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
	require.NoError(t, err, "description HTTP request parsing failed")

	_, err = tx.ProcessRequest(req)
	require.NoError(t, err, "failed to load the HTTP request")

	// There is no problem loading the rules
	c := 0
	r := waf.Rules.FindByID(100)
	for r != nil {
		c++
		r = r.Chain
	}
	require.Equal(t, 3, c, "failed to compile multiple chains")

	// Why is the number of matches 4
	macro, err := coraza.NewMacro("%{tx.count}")
	require.NoError(t, err)

	c, _ = strconv.Atoi(macro.Expand(tx))
	require.Equal(t, 6, c)
}

func TestIssue176(t *testing.T) {
	waf := coraza.NewWaf()
	rules := `SecRule REQUEST_COOKIES:sessionId "test" "id:1,phase:1,deny,log,msg:'test rule',logdata:'Matched %{MATCHED_VAR_NAME}'"`
	parser, err := NewParser(waf)
	require.NoError(t, err)

	err = parser.FromString(rules)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddRequestHeader("Cookie", "sessionId=test")
	it := tx.ProcessRequestHeaders()
	require.NotNil(t, it, "error test for github issue #176")

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
	require.NoError(t, err)

	err = parser.FromString(rules)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddRequestHeader("Content-Type", "text/html; charset=utf-8")
	it := tx.ProcessRequestHeaders()
	require.Nil(t, it, "failed test for rx captured")
}

func Test941310(t *testing.T) {
	waf := coraza.NewWaf()
	rules := `SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx \xbc[^\xbe>]*[\xbe>]|<[^\xbe]*\xbe" \
    "id:941310,\
    phase:2,\
    deny,\
    capture,\
    t:none,t:lowercase,t:urlDecode,t:htmlEntityDecode,t:jsDecode,\
    msg:'US-ASCII Malformed Encoding XSS Filter - Attack Detected',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-tomcat',\
    tag:'attack-xss',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'capec/1000/152/242',\
    ver:'OWASP_CRS/3.4.0-dev',\
    severity:'CRITICAL',\
    chain"
    SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?:\xbc\s*/\s*[^\xbe>]*[\xbe>])|(?:<\s*/\s*[^\xbe]*\xbe)" \
        "t:none,t:lowercase,t:urlDecode,t:htmlEntityDecode,t:jsDecode,\
        ctl:auditLogParts=+E,\
        setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
        setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"`
	parser, err := NewParser(waf)
	require.NoError(t, err)

	err = parser.FromString(rules)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddArgument("POST", "var", `\\xbcscript\\xbealert(\xa2XSS\xa2)\xbc/script\xbe`)
	it, err := tx.ProcessRequestBody()
	require.NoError(t, err)
	require.NotNil(t, it, "non utf-8 rx test fails")
}

func TestArgumentNamesCaseSensitive(t *testing.T) {
	waf := coraza.NewWaf()
	rules := `SecRule ARGS_NAMES "Test1" "id:3, phase:2, log, deny"`
	parser, err := NewParser(waf)
	require.NoError(t, err)

	err = parser.FromString(rules)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddArgument("POST", "Test1", "Xyz")
	it, err := tx.ProcessRequestBody()
	require.NoError(t, err)
	require.NotNil(t, it, "failed to test argument names case sensitive: same case nomatch")

	tx = waf.NewTransaction()
	tx.AddArgument("POST", "TEST1", "Xyz")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.Nil(t, it, "failed to test argument names case sensitive: Upper case argument name matched")

	tx = waf.NewTransaction()
	tx.AddArgument("POST", "test1", "Xyz")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.Nil(t, it, "failed to test argument names case sensitive: Lower case argument name matched")
}

func TestArgumentsCaseSensitive(t *testing.T) {
	waf := coraza.NewWaf()
	rules := `SecRule ARGS:Test1 "Xyz" "id:3, phase:2, log, deny"`
	parser, err := NewParser(waf)
	require.NoError(t, err)

	err = parser.FromString(rules)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddArgument("POST", "Test1", "Xyz")
	it, err := tx.ProcessRequestBody()
	require.NoError(t, err)
	require.NotNilf(t, it, "failed to test arguments value match: Same case argument name, %+v\n", tx.MatchedRules)

	tx = waf.NewTransaction()
	tx.AddArgument("POST", "TEST1", "Xyz")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.NotNilf(t, it, "failed to test arguments value match: Upper case argument name, %+v\n", tx.MatchedRules)

	tx = waf.NewTransaction()
	tx.AddArgument("POST", "test1", "Xyz")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.NotNilf(t, it, "failed to test arguments value match: Lower case argument name, %+v\n", tx.MatchedRules)

	tx = waf.NewTransaction()
	tx.AddArgument("POST", "test1", "xyz")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.Nil(t, it, "failed to test arguments value: different value case")

	tx = waf.NewTransaction()
	tx.AddArgument("POST", "test1", "XYZ")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.Nil(t, it, "failed to test arguments value: different value case")
}

func TestCookiesCaseSensitive(t *testing.T) {
	waf := coraza.NewWaf()
	rules := `SecRule REQUEST_COOKIES:Test1 "Xyz" "id:3, phase:2, log, deny"`
	parser, err := NewParser(waf)
	require.NoError(t, err)

	err = parser.FromString(rules)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddRequestHeader("cookie", "Test1=Xyz")
	it, err := tx.ProcessRequestBody()
	require.NoError(t, err)
	require.NotNil(t, it, "failed to test cookies case sensitive")

	tx = waf.NewTransaction()
	tx.AddRequestHeader("cookie", "TEST1=Xyz")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.NotNil(t, it, "failed to test cookies case sensitive")

	tx = waf.NewTransaction()
	tx.AddRequestHeader("cookie", "test1=Xyz")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.NotNil(t, it, "failed to test cookies case sensitive")

	tx = waf.NewTransaction()
	tx.AddRequestHeader("cookie", "test1=xyz")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.Nil(t, it, "failed to test cookies value case sensitive")

	tx = waf.NewTransaction()
	tx.AddRequestHeader("cookie", "test1=XYZ")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.Nil(t, it, "failed to test cookies value case sensitive")
}

func TestHeadersCaseSensitive(t *testing.T) {
	waf := coraza.NewWaf()
	rules := `SecRule REQUEST_HEADERS:Test1 "Xyz" "id:3, phase:2, log, deny"`
	parser, err := NewParser(waf)
	require.NoError(t, err)

	err = parser.FromString(rules)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddRequestHeader("Test1", "Xyz")
	it, err := tx.ProcessRequestBody()
	require.NoError(t, err)
	require.NotNil(t, it, "failed to test cookies case sensitive")

	tx = waf.NewTransaction()
	tx.AddRequestHeader("TEST1", "Xyz")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.NotNil(t, it, "failed to test cookies case sensitive")

	tx = waf.NewTransaction()
	tx.AddRequestHeader("test1", "Xyz")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.NotNil(t, it, "failed to test cookies case sensitive")

	tx = waf.NewTransaction()
	tx.AddRequestHeader("test1", "xyz")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.Nil(t, it, "failed to test cookies value case sensitive")

	tx = waf.NewTransaction()
	tx.AddRequestHeader("test1", "XYZ")
	it, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.Nil(t, it, "failed to test cookies value case sensitive")
}

func TestParameterPollution(t *testing.T) {
	waf := coraza.NewWaf()
	rules := `SecRule Args:TESt1 "Xyz" "id:3, phase:2, log, pass"`
	parser, err := NewParser(waf)
	require.NoError(t, err)

	err = parser.FromString(rules)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddArgument("POST", "test1", "xyz")
	tx.AddArgument("POST", "Test1", "Xyz")
	tx.AddArgument("POST", "TEST1", "XYZ")

	_, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.Lenf(t, tx.MatchedRules, 1, "failed to test arguments pollution: Single match fixed case:\n%+v", tx.MatchedRules)
	require.Lenf(t, tx.MatchedRules[0].MatchedDatas, 1, "failed to test arguments pollution:\n%+v",
		len(tx.MatchedRules[0].MatchedDatas), tx.MatchedRules)

	tx = waf.NewTransaction()
	tx.AddArgument("POST", "test1", "xyz")
	tx.AddArgument("POST", "Test1", "Xyz")
	tx.AddArgument("POST", "tesT1", "Xyz")
	tx.AddArgument("POST", "TEST1", "XYZ")
	_, err = tx.ProcessRequestBody()
	require.NoError(t, err)
	require.Lenf(t, tx.MatchedRules, 1, "failed to test arguments pollution: Multiple match mixed case: %d, %+v\n",
		len(tx.MatchedRules), tx.MatchedRules)
	require.Lenf(t, tx.MatchedRules[0].MatchedDatas, 2, "failed to test arguments pollution. Found matches: %d, %+v\n",
		len(tx.MatchedRules[0].MatchedDatas), tx.MatchedRules)
}

func TestURIQueryParamCaseSensitive(t *testing.T) {
	waf := coraza.NewWaf()
	rules := `SecRule ARGS:Test1 "@contains SQLI" "id:3, phase:2, log, pass"`
	parser, err := NewParser(waf)
	require.NoError(t, err)

	err = parser.FromString(rules)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.ProcessURI("/url?Test1='SQLI", "POST", "HTTP/1.1")
	_, err = tx.ProcessRequestBody()
	require.NoError(t, err)

	require.Lenf(t, tx.MatchedRules, 1, "failed to test uri query param: Same case arg name: %d, %+v\n",
		len(tx.MatchedRules), tx.MatchedRules)

	require.Lenf(t, tx.MatchedRules[0].MatchedDatas, 1, "failed to test uri query param. Found matches: %d, %+v\n",
		len(tx.MatchedRules[0].MatchedDatas), tx.MatchedRules)

	require.True(t, isMatchData(tx.MatchedRules[0].MatchedDatas, "Test1"), "Key did not match")

	tx = waf.NewTransaction()
	tx.ProcessURI("/test?test1='SQLI&Test1='SQLI&TEST1='SQLI", "POST", "HTTP/1.1")
	_, err = tx.ProcessRequestBody()
	require.NoError(t, err)

	require.Lenf(t, tx.MatchedRules, 1, "failed to test qparam pollution: Multiple arg different case: %d, %+v\n",
		len(tx.MatchedRules), tx.MatchedRules)

	tx.PrintLog()

	require.Lenf(t, tx.MatchedRules[0].MatchedDatas, 3, "failed to test uri query param. Found matches: %d, %+v\n",
		len(tx.MatchedRules[0].MatchedDatas), tx.MatchedRules)

	require.True(t, isMatchData(tx.MatchedRules[0].MatchedDatas, "Test1"), "Key did not match")
}

func TestURIQueryParamNameCaseSensitive(t *testing.T) {
	waf := coraza.NewWaf()
	rules := `SecRule ARGS_NAMES "Test1" "id:3, phase:2, log, pass"`
	parser, err := NewParser(waf)
	require.NoError(t, err)

	err = parser.FromString(rules)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.ProcessURI("/url?Test1='SQLI", "POST", "HTTP/1.1")
	_, err = tx.ProcessRequestBody()
	require.NoError(t, err)

	require.Lenf(t, tx.MatchedRules, 1, "failed to test uri query param: Same case arg name:%d, %+v\n",
		len(tx.MatchedRules), tx.MatchedRules)

	require.Lenf(t, tx.MatchedRules[0].MatchedDatas, 1, "failed to test uri query param. Expected: 1, Found matches: %d, %+v\n",
		len(tx.MatchedRules[0].MatchedDatas), tx.MatchedRules)

	require.True(t, isMatchData(tx.MatchedRules[0].MatchedDatas, "Test1"), "key did not match")

	tx = waf.NewTransaction()
	tx.ProcessURI("/test?test1='SQLI&Test1='SQLI&TEST1='SQLI", "POST", "HTTP/1.1")
	_, err = tx.ProcessRequestBody()
	require.NoError(t, err)

	require.Lenf(t, tx.MatchedRules, 1, "failed to test qparam pollution: Multiple arg different case:",
		len(tx.MatchedRules))

	tx.PrintLog()
	require.Lenf(t, tx.MatchedRules[0].MatchedDatas, 1, "failed to test uri query param. Expected: 1, Found matches: %d, %+v\n",
		len(tx.MatchedRules[0].MatchedDatas), tx.MatchedRules)

	require.True(t, isMatchData(tx.MatchedRules[0].MatchedDatas, "Test1"), "key did not match")
}

func isMatchData(mds []coraza.MatchData, key string) (result bool) {
	result = false
	for _, m := range mds {
		if m.Key == key {
			result = true
			break
		}
	}
	return result
}

func Test930110_10(t *testing.T) {
	waf := coraza.NewWaf()
	rules := `
SecRequestBodyAccess On
SecRule REQUEST_URI|ARGS|REQUEST_HEADERS|!REQUEST_HEADERS:Referer|FILES|XML:/* "@rx (?:(?:^|[\x5c/])\.{2,3}[\x5c/]|[\x5c/]\.{2,3}(?:[\x5c/]|$))" \
    "id:930110,\
    phase:2,\
    deny,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,t:cmdLine,\
    msg:'Path Traversal Attack (/../) or (/.../)',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-lfi',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'capec/1000/255/153/126',\
    ver:'OWASP_CRS/3.4.0-dev',\
    severity:'CRITICAL',\
    multiMatch,\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}',\
    setvar:'tx.lfi_score=+%{tx.critical_anomaly_score}'"
`

	parser, err := NewParser(waf)
	require.NoError(t, err)

	err = parser.FromString(rules)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.AddRequestHeader("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryABCDEFGIJKLMNOPQ")

	body := strings.NewReader(`
------WebKitFormBoundaryABCDEFGIJKLMNOPQ
Content-Disposition: form-data; name="file"; filename="../1.7z"
Content-Type: application/octet-stream

BINARYDATA
------WebKitFormBoundaryABCDEFGIJKLMNOPQ--`)
	_, err = io.Copy(tx.RequestBodyBuffer, body)
	require.NoError(t, err)

	it, err := tx.ProcessRequestBody()
	require.NoError(t, err)
	require.NotNil(t, it, "failed test for rx captured")
}
