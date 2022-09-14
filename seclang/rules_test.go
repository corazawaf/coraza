// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"context"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

func TestRuleMatch(t *testing.T) {
	waf := coraza.NewWAF()
	parser := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On
		SecDefaultAction "phase:1,deny,status:403,log"
		SecRule REMOTE_ADDR "^127.*" "id:1,phase:1"
		SecRule REMOTE_ADDR "!@rx 127.0.0.1" "id:2,phase:1"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction(context.Background())
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
	waf := coraza.NewWAF()
	parser := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On
		SecDefaultAction "phase:1,deny,status:403,log"
		SecRule ARGS:/^id_.*/ "123" "phase:1, id:1"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction(context.Background())
	tx.AddArgument("GET", "id_test", "123")
	tx.ProcessRequestHeaders()
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
	waf := coraza.NewWAF()
	parser := NewParser(waf)
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

	tx := waf.NewTransaction(context.Background())
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
	waf := coraza.NewWAF()
	parser := NewParser(waf)
	err := parser.FromString(`
		SecAuditEngine On
		SecAction "id:4482,log,auditlog, msg:'test'"
		SecAuditLogParts ABCDEFGHIJK
		SecRuleEngine On
	`)
	if err != nil {
		t.Error(err)
	}
	tx := waf.NewTransaction(context.Background())
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
	waf := coraza.NewWAF()
	logs := []string{}
	waf.SetErrorLogCb(func(mr types.MatchedRule) {
		logs = append(logs, mr.ErrorLog(403))
	})
	parser := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS ".*" "phase:1, id:1,capture,log,setvar:'tx.arg_%{tx.0}=%{tx.0}'"
		SecAction "id:2,phase:1,log,setvar:'tx.test=ok'"
		SecAction "id:3,phase:1,nolog"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction(context.Background())
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
}

func TestRuleChains(t *testing.T) {
	waf := coraza.NewWAF()
	parser := NewParser(waf)
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
	tx := waf.NewTransaction(context.Background())
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules) != 1 {
		t.Errorf("failed to match rules with %d matches, expected 1", len(tx.MatchedRules))
	}
}

func TestTagsAreNotPrintedTwice(t *testing.T) {
	waf := coraza.NewWAF()
	logs := []string{}
	waf.SetErrorLogCb(func(mr types.MatchedRule) {
		logs = append(logs, mr.ErrorLog(403))
	})
	parser := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS ".*" "phase:1, id:1,log,tag:'some1',tag:'some2'"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction(context.Background())
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
	waf := coraza.NewWAF()
	logs := []string{}
	waf.SetErrorLogCb(func(mr types.MatchedRule) {
		logs = append(logs, mr.ErrorLog(403))
	})
	parser := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS "123" "phase:1, id:1,log,deny,status:500"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction(context.Background())
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
	waf := coraza.NewWAF()
	p := NewParser(waf)
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
	waf := coraza.NewWAF()
	logs := []string{}
	waf.SetErrorLogCb(func(mr types.MatchedRule) {
		logs = append(logs, mr.ErrorLog(403))
	})
	parser := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS|REQUEST_HEADERS|!ARGS:test1 ".*" "phase:1, id:1,log,tag:'some1',tag:'some2'"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction(context.Background())
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
	waf := coraza.NewWAF()
	parser := NewParser(waf)
	err := parser.FromString(`
	SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "phase:1,id:1,log,deny,status:403,chain"
	SecRule REQUEST_HEADERS:Content-Length "!@rx ^0?$"`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction(context.Background())
	tx.ProcessURI("/test", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Content-Length", "15")
	if it := tx.ProcessRequestHeaders(); it == nil {
		t.Error("failed to interrupt")
	}
}

func TestTxIssue147(t *testing.T) {
	// https://github.com/corazawaf/coraza/issues/147
	waf := coraza.NewWAF()
	parser := NewParser(waf)
	err := parser.FromString(`SecRule RESPONSE_BODY "@rx ^#!\s?/" "id:950140,phase:4,log,deny,status:403"`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction(context.Background())
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

func TestIssue176(t *testing.T) {
	waf := coraza.NewWAF()
	rules := `SecRule REQUEST_COOKIES:sessionId "test" "id:1,phase:1,deny,log,msg:'test rule',logdata:'Matched %{MATCHED_VAR_NAME}'"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction(context.Background())
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
	//	tx = waf.NewTransaction(context.Background())
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
	//	tx = waf.NewTransaction(context.Background())
	//	tx.AddArgument("GET", "Test2", "123")
	//	it = tx.ProcessRequestHeaders()
	//	if it != nil {
	//		t.Error("failed to test argument case-sensitive")
	//	}
}

func TestRxCapture(t *testing.T) {
	waf := coraza.NewWAF()
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
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction(context.Background())
	tx.AddRequestHeader("Content-Type", "text/html; charset=utf-8")
	it := tx.ProcessRequestHeaders()
	if it != nil {
		t.Error("failed test for rx captured")
	}
}

func TestUnicode(t *testing.T) {
	waf := coraza.NewWAF()
	rules := `SecRule ARGS "@rx \u30cf\u30ed\u30fc" "id:101,phase:2,t:lowercase,deny"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction(context.Background())
	tx.AddArgument("POST", "var", `ハローワールド`)
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("non utf-8 rx test fails")
	}
}

func Test941310(t *testing.T) {
	// TODO(anuraaga): Go regex only supports utf8 strings. This means to match non-utf8 would require escaping the
	// input into ASCII before matching. Just the presence of a non-utf8 matcher, like in CRS, would cause this escaping
	// to be required on all input. This is probably not worth it performance-wise, as with Go few HTTP libraries would
	// support non-utf8 anyways.

	// not supported on TinyGo
	// t.Skip("non-utf8 regex not supported")

	//waf := coraza.NewWAF()
	//rules := `SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx \xbc[^\xbe>]*[\xbe>]|<[^\xbe]*\xbe" \
	//"id:941310,\
	//phase:2,\
	//deny,\
	//capture,\
	//t:none,t:lowercase,t:urlDecode,t:htmlEntityDecode,t:jsDecode,\
	//msg:'US-ASCII Malformed Encoding XSS Filter - Attack Detected',\
	//logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
	//tag:'application-multi',\
	//tag:'language-multi',\
	//tag:'platform-tomcat',\
	//tag:'attack-xss',\
	//tag:'paranoia-level/1',\
	//tag:'OWASP_CRS',\
	//tag:'capec/1000/152/242',\
	//ver:'OWASP_CRS/3.4.0-dev',\
	//severity:'CRITICAL',\
	//chain"
	//SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?:\xbc\s*/\s*[^\xbe>]*[\xbe>])|(?:<\s*/\s*[^\xbe]*\xbe)" \
	//    "t:none,t:lowercase,t:urlDecode,t:htmlEntityDecode,t:jsDecode,\
	//    ctl:auditLogParts=+E,\
	//    setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
	//    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"`
	//parser := NewParser(waf)
	//
	//err := parser.FromString(rules)
	//if err != nil {
	//	t.Error()
	//	return
	//}
	//
	//tx := waf.NewTransaction(context.Background())
	//tx.AddArgument("POST", "var", `\\xbcscript\\xbealert(\xa2XSS\xa2)\xbc/script\xbe`)
	//it, err := tx.ProcessRequestBody()
	//if err != nil {
	//	t.Error(err)
	//}
	//if it == nil {
	//	t.Error("non utf-8 rx test fails")
	//}
}

func TestArgumentNamesCaseSensitive(t *testing.T) {
	waf := coraza.NewWAF()
	rules := `SecRule ARGS_NAMES "Test1" "id:3, phase:2, log, deny"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}
	/*
		tx := waf.NewTransaction(context.Background())
		tx.AddArgument("POST", "Test1", "Xyz")
		it, err := tx.ProcessRequestBody()
		if err != nil {
			t.Error(err)
		}
		if it == nil {
			t.Error("failed to test argument names case sensitive: same case nomatch")
		}

		tx = waf.NewTransaction(context.Background())
		tx.AddArgument("POST", "TEST1", "Xyz")
		it, err = tx.ProcessRequestBody()
		if err != nil {
			t.Error(err)
		}
		if it != nil {
			t.Error("failed to test argument names case sensitive: Upper case argument name matched")
		}

		tx = waf.NewTransaction(context.Background())
		tx.AddArgument("POST", "test1", "Xyz")
		it, err = tx.ProcessRequestBody()
		if err != nil {
			t.Error(err)
		}
		if it != nil {
			t.Error("failed to test argument names case sensitive: Lower case argument name matched")
		}
	*/
}

func TestArgumentsCaseSensitive(t *testing.T) {
	waf := coraza.NewWAF()
	rules := `SecRule ARGS:Test1 "Xyz" "id:3, phase:2, log, deny"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction(context.Background())
	tx.AddArgument("POST", "Test1", "Xyz")
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Errorf("failed to test arguments value match: Same case argument name, %+v\n", tx.MatchedRules)
	}

	tx = waf.NewTransaction(context.Background())
	tx.AddArgument("POST", "TEST1", "Xyz")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Errorf("failed to test arguments value match: Upper case argument name, %+v\n", tx.MatchedRules)
	}

	tx = waf.NewTransaction(context.Background())
	tx.AddArgument("POST", "test1", "Xyz")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Errorf("failed to test arguments value match: Lower case argument name, %+v\n", tx.MatchedRules)
	}

	tx = waf.NewTransaction(context.Background())
	tx.AddArgument("POST", "test1", "xyz")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Error("failed to test arguments value: different value case")
	}

	tx = waf.NewTransaction(context.Background())
	tx.AddArgument("POST", "test1", "XYZ")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Error("failed to test arguments value: different value case")
	}
}

func TestCookiesCaseSensitive(t *testing.T) {
	waf := coraza.NewWAF()
	rules := `SecRule REQUEST_COOKIES:Test1 "Xyz" "id:3, phase:2, log, deny"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction(context.Background())
	tx.AddRequestHeader("cookie", "Test1=Xyz")
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("failed to test cookies case sensitive")
	}

	tx = waf.NewTransaction(context.Background())
	tx.AddRequestHeader("cookie", "TEST1=Xyz")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("failed to test cookies case sensitive")
	}

	tx = waf.NewTransaction(context.Background())
	tx.AddRequestHeader("cookie", "test1=Xyz")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("failed to test cookies case sensitive")
	}

	tx = waf.NewTransaction(context.Background())
	tx.AddRequestHeader("cookie", "test1=xyz")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Error("failed to test cookies value case sensitive")
	}

	tx = waf.NewTransaction(context.Background())
	tx.AddRequestHeader("cookie", "test1=XYZ")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Error("failed to test cookies value case sensitive")
	}
}

func TestHeadersCaseSensitive(t *testing.T) {
	waf := coraza.NewWAF()
	rules := `SecRule REQUEST_HEADERS:Test1 "Xyz" "id:3, phase:2, log, deny"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction(context.Background())
	tx.AddRequestHeader("Test1", "Xyz")
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("failed to test cookies case sensitive")
	}

	tx = waf.NewTransaction(context.Background())
	tx.AddRequestHeader("TEST1", "Xyz")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("failed to test cookies case sensitive")
	}

	tx = waf.NewTransaction(context.Background())
	tx.AddRequestHeader("test1", "Xyz")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("failed to test cookies case sensitive")
	}

	tx = waf.NewTransaction(context.Background())
	tx.AddRequestHeader("test1", "xyz")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Error("failed to test cookies value case sensitive")
	}

	tx = waf.NewTransaction(context.Background())
	tx.AddRequestHeader("test1", "XYZ")
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Error("failed to test cookies value case sensitive")
	}
}

func TestParameterPollution(t *testing.T) {
	waf := coraza.NewWAF()
	rules := `SecRule Args:TESt1 "Xyz" "id:3, phase:2, log, pass"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction(context.Background())
	tx.AddArgument("POST", "test1", "xyz")
	tx.AddArgument("POST", "Test1", "Xyz")
	tx.AddArgument("POST", "TEST1", "XYZ")
	_, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}

	if len(tx.MatchedRules) == 1 {
		if len(tx.MatchedRules[0].MatchedDatas) != 1 {
			t.Errorf("failed to test arguments pollution. Found matches: %d, %+v\n",
				len(tx.MatchedRules[0].MatchedDatas), tx.MatchedRules)
		}
	} else {
		t.Errorf("failed to test arguments pollution: Single match fixed case: %d, %+v\n",
			len(tx.MatchedRules), tx.MatchedRules)
	}

	tx = waf.NewTransaction(context.Background())
	tx.AddArgument("POST", "test1", "xyz")
	tx.AddArgument("POST", "Test1", "Xyz")
	tx.AddArgument("POST", "tesT1", "Xyz")
	tx.AddArgument("POST", "TEST1", "XYZ")
	_, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if len(tx.MatchedRules) == 1 {
		if len(tx.MatchedRules[0].MatchedDatas) != 2 {
			t.Errorf("failed to test arguments pollution. Found matches: %d, %+v\n",
				len(tx.MatchedRules[0].MatchedDatas), tx.MatchedRules)
		}
	} else {
		t.Errorf("failed to test arguments pollution: Multiple match mixed case: %d, %+v\n",
			len(tx.MatchedRules), tx.MatchedRules)
	}

}

func TestURIQueryParamCaseSensitive(t *testing.T) {
	waf := coraza.NewWAF()
	rules := `SecRule ARGS:Test1 "@contains SQLI" "id:3, phase:2, log, pass"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction(context.Background())
	tx.ProcessURI("/url?Test1='SQLI", "POST", "HTTP/1.1")
	_, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}

	if len(tx.MatchedRules) == 1 {
		if len(tx.MatchedRules[0].MatchedDatas) != 1 {
			t.Errorf("failed to test uri query param. Found matches: %d, %+v\n",
				len(tx.MatchedRules[0].MatchedDatas), tx.MatchedRules)
		}
		if !isMatchData(tx.MatchedRules[0].MatchedDatas, "Test1") {
			t.Error("Key did not match: Test1 !=", tx.MatchedRules[0])
		}
	} else {
		t.Errorf("failed to test uri query param: Same case arg name: %d, %+v\n",
			len(tx.MatchedRules), tx.MatchedRules)
	}

	tx = waf.NewTransaction(context.Background())
	tx.ProcessURI("/test?test1='SQLI&Test1='SQLI&TEST1='SQLI", "POST", "HTTP/1.1")
	_, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}

	if len(tx.MatchedRules) == 1 {
		if len(tx.MatchedRules[0].MatchedDatas) != 3 {
			t.Errorf("failed to test uri query param. Found matches: %d, %+v\n",
				len(tx.MatchedRules[0].MatchedDatas), tx.MatchedRules)
		}
		if !isMatchData(tx.MatchedRules[0].MatchedDatas, "Test1") {
			t.Error("Key did not match: Test1 !=", tx.MatchedRules[0])
		}
	} else {
		t.Errorf("failed to test qparam pollution: Multiple arg different case: %d, %+v\n",
			len(tx.MatchedRules), tx.MatchedRules)
	}
}

/*
func TestURIQueryParamNameCaseSensitive(t *testing.T) {
	waf := coraza.NewWAF()
	rules := `SecRule ARGS_NAMES "Test1" "id:3, phase:2, log, pass"`
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

	tx := waf.NewTransaction(context.Background())
	tx.ProcessURI("/url?Test1='SQLI", "POST", "HTTP/1.1")
	_, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}

	if len(tx.MatchedRules) == 1 {
		if len(tx.MatchedRules[0].MatchedDatas) != 1 {
			t.Errorf("failed to test uri query param. Expected: 1, Found matches: %d, %+v\n",
				len(tx.MatchedRules[0].MatchedDatas), tx.MatchedRules)
		}
		if !isMatchData(tx.MatchedRules[0].MatchedDatas, "Test1") {
			t.Error("Key did not match: Test1 !=", tx.MatchedRules[0])
		}
	} else {
		t.Errorf("failed to test uri query param: Same case arg name:%d, %+v\n",
			len(tx.MatchedRules), tx.MatchedRules)
	}

	tx = waf.NewTransaction(context.Background())
	tx.ProcessURI("/test?test1='SQLI&Test1='SQLI&TEST1='SQLI", "POST", "HTTP/1.1")
	_, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}

	if len(tx.MatchedRules) == 1 {
		if len(tx.MatchedRules[0].MatchedDatas) != 1 {
			t.Errorf("Failed to test uri query param. Expected: 1, Found matches: %d, %+v\n",
				len(tx.MatchedRules[0].MatchedDatas), tx.MatchedRules)
		}
		if !isMatchData(tx.MatchedRules[0].MatchedDatas, "Test1") {
			t.Error("Key did not match: Test1 !=", tx.MatchedRules[0])
		}
	} else {
		t.Error("failed to test qparam pollution: Multiple arg different case:",
			len(tx.MatchedRules))
	}
}
*/

func isMatchData(mds []types.MatchData, key string) (result bool) {
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
	waf := coraza.NewWAF()
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

	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Fatal(err)
		return
	}

	tx := waf.NewTransaction(context.Background())
	tx.AddRequestHeader("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryABCDEFGIJKLMNOPQ")

	body := strings.NewReader(`
------WebKitFormBoundaryABCDEFGIJKLMNOPQ
Content-Disposition: form-data; name="file"; filename="../1.7z"
Content-Type: application/octet-stream

BINARYDATA
------WebKitFormBoundaryABCDEFGIJKLMNOPQ--`)
	_, err = io.Copy(tx.RequestBodyBuffer, body)
	if err != nil {
		t.Error(err)
		return
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
		return
	}
	if it == nil {
		t.Error("failed test for rx captured")
	}
}
