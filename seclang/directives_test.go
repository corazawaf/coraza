// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

func Test_NonImplementedDirective(t *testing.T) {
	rules := []string{
		`SecSensorId WAFSensor01`,
		`SecConnReadStateLimit 50 "!@ipMatch 127.0.0.1"`,
		`SecPcreMatchLimit 1500`,
		`SecPcreMatchLimitRecursion 1500`,
		`SecHttpBlKey whdkfieyhtnf`,
		`SecHashMethodRx HashHref "product_info|list_product"`,
		`SecHashMethodPm HashHref“product_info list_product”`,
		`SecHashParam "hmac"`,
		`SecHashKey "this_is_my_key" KeyOnly`,
		`SecHashEngine On`,
	}
	w := coraza.NewWAF()
	p := NewParser(w)
	for _, rule := range rules {
		err := p.FromString(rule)
		if err != nil {
			t.Errorf("failed to set directive: %s", rule)
		}
	}
}

func Test_directive(t *testing.T) {
	w := coraza.NewWAF()
	p := NewParser(w)
	if err := p.FromString("SecWebAppId test123"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.WebAppID != "test123" {
		t.Error("failed to set SecWebAppId")
	}
	if err := p.FromString("SecUploadKeepFiles On"); err != nil {
		t.Error("failed to set parser from string")
	}
	if !w.UploadKeepFiles {
		t.Error("failed to set SecUploadKeepFiles")
	}
	if err := p.FromString("SecUploadFileMode 0700"); err != nil {
		t.Error("failed to set parser from string")
	}
	if err := p.FromString("SecUploadFileLimit 1000"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.UploadFileLimit != 1000 {
		t.Error("failed to set SecUploadFileLimit")
	}
	if err := p.FromString("SecUploadDir /tmp"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.UploadDir != "/tmp" {
		t.Error("failed to set SecUploadDir")
	}
	if err := p.FromString("SecTmpDir /tmp"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.TmpDir != "/tmp" {
		t.Error("failed to set SecTmpDir")
	}
	if err := p.FromString("SecSensorId test"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.SensorID != "test" {
		t.Error("failed to set SecSensorId")
	}
	if err := p.FromString("SecRuleEngine DetectionOnly"); err != nil {
		t.Error("failed to set parser from string")
	}
	if w.RuleEngine != types.RuleEngineDetectionOnly {
		t.Errorf("failed to set SecRuleEngine, got %s and expected %s", w.RuleEngine.String(), types.RuleEngineDetectionOnly.String())
	}
	if err := p.FromString(`SecAction "id:1,tag:test"`); err != nil {
		t.Error("failed to set parser from string")
	}
	if err := p.FromString("SecRuleRemoveByTag test"); err != nil {
		t.Error("failed to set parser from string")
	}
	if p.options.WAF.Rules.Count() != 0 {
		t.Error("Failed to remove rule with SecRuleRemoveByTag")
	}
	if err := p.FromString(`SecAction "id:1,msg:'test'"`); err != nil {
		t.Error("failed to set parser from string")
	}
	if err := p.FromString("SecRuleRemoveByMsg test"); err != nil {
		t.Error("failed to set parser from string")
	}
	if p.options.WAF.Rules.Count() != 0 {
		t.Error("Failed to remove rule with SecRuleRemoveByMsg")
	}
	if err := p.FromString(`SecAction "id:1"`); err != nil {
		t.Error("failed to set parser from string")
	}
	if err := p.FromString("SecRuleRemoveById 1"); err != nil {
		t.Error("failed to set parser from string")
	}
	if p.options.WAF.Rules.Count() != 0 {
		t.Error("Failed to remove rule with SecRuleRemoveById")
	}
	if err := p.FromString("SecResponseBodyMimeTypesClear"); err != nil {
		t.Error("failed to set parser from string")
	}
	if len(p.options.WAF.ResponseBodyMimeTypes) != 0 {
		t.Error("failed to set SecResponseBodyMimeTypesClear")
	}
	if err := p.FromString("SecResponseBodyMimeType text/html"); err != nil {
		t.Error("failed to set parser from string")
	}
	if p.options.WAF.ResponseBodyMimeTypes[0] != "text/html" {
		t.Error("failed to set SecResponseBodyMimeType")
	}
	if err := p.FromString(`SecServerSignature "Microsoft-IIS/6.0"`); err != nil {
		t.Error("failed to set directive: SecServerSignature")
	}
	if err := p.FromString(`SecRequestBodyInMemoryLimit 131072`); err != nil {
		t.Error("failed to set directive: SecRequestBodyInMemoryLimit")
	}
	if err := p.FromString(`SecRemoteRulesFailAction Abort`); err != nil {
		t.Error("failed to set directive: SecRemoteRulesFailAction")
	}
}

func TestDebugDirectives(t *testing.T) {
	waf := coraza.NewWaf()
	tmpf, err := ioutil.TempFile("/tmp", "*.log")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmpf.Name())
	tmp := tmpf.Name()
	p, _ := NewParser(waf)
	err = directiveSecDebugLog(&DirectiveOptions{
		Waf:       waf,
		Arguments: tmp,
	})
	if err != nil {
		t.Error(err)
	}
	if err := directiveSecDebugLogLevel(&DirectiveOptions{
		Waf:       waf,
		Arguments: "5",
	}); err != nil {
		t.Error(err)
	}
	p.options.Waf.Logger.Info("abc123")
	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(string(data), "abc123") {
		t.Errorf("failed to write info log, got %q", data)
	}
}

func TestSecAuditLogDirectivesConcurrent(t *testing.T) {
	waf := coraza.NewWaf()
	auditpath := "/tmp/"
	parser, _ := NewParser(waf)
	if err := parser.FromString(`
	SecAuditLog /tmp/audit.log
	SecAuditLogFormat json
	SecAuditLogDir /tmp
	SecAuditLogDirMode 0777
	SecAuditLogFileMode 0777
	SecAuditLogType concurrent
	`); err != nil {
		t.Error(err)
	}
	id := utils.SafeRandom(10)
	if waf.AuditLogWriter == nil {
		t.Error("Invalid audit logger (nil)")
		return
	}
	if err := waf.AuditLogWriter.Write(&loggers.AuditLog{
		Parts: types.AuditLogParts("ABCDEFGHIJKZ"),
		Transaction: loggers.AuditTransaction{
			ID: id,
		},
	}); err != nil {
		t.Error(err)
	}
	f, err := findFileContaining(auditpath, id)
	if err != nil {
		t.Error(err)
	}
	data, err := ioutil.ReadFile(f)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(string(data), id) {
		t.Error("failed to write audit log")
	}
	// we test it is a valid json
	var j map[string]interface{}
	if err := json.Unmarshal(data, &j); err != nil {
		t.Error(err)
	}
}

func TestSecRuleUpdateTargetBy(t *testing.T) {
	waf := coraza.NewWAF()
	rule, err := ParseRule(RuleOptions{
		Data:         "REQUEST_URI \"^/test\" \"id:181,tag:test\"",
		WAF:          waf,
		WithOperator: true,
	})
	if err != nil {
		t.Error(err)
	}
	if err := waf.Rules.Add(rule); err != nil {
		t.Error(err)
	}
	if waf.Rules.Count() != 1 {
		t.Error("Failed to add rule")
	}
	if err := directiveSecRuleUpdateTargetByID(&DirectiveOptions{
		WAF:       waf,
		Arguments: "181 \"REQUEST_HEADERS\"",
	}); err != nil {
		t.Error(err)
	}

}

func TestInvalidBooleanForDirectives(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	if err := p.FromString("SecIgnoreRuleCompilationErrors sure"); err == nil {
		t.Error("failed to error on invalid boolean")
	}
}

func TestInvalidRulesWithIgnoredErrors(t *testing.T) {
	directives := `
	SecRule REQUEST_URI "@no_op ^/test" "id:181,tag:test"
	SecRule REQUEST_URI "@no_op ^/test" "id:200,tag:test,invalid:5"
	SecRule REQUEST_URI "@rx ^/test" "id:181,tag:repeated-id"
	`
	waf := coraza.NewWAF()
	p := NewParser(waf)
	if err := p.FromString("secignorerulecompilationerrors On\n" + directives); err != nil {
		t.Error(err)
	}
	waf = coraza.NewWAF()
	p = NewParser(waf)
	if err := p.FromString(directives); err == nil {
		t.Error("failed to error on invalid rule")
	}
}

func TestRegisterDirective(t *testing.T) {
	directive := func(options *DirectiveOptions) error {
		return nil
	}
	RegisterDirective("test", directive)
	if _, ok := directivesMap["test"]; !ok {
		t.Error("failed to register directive")
  }
}


func TestSecDataset(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	if err := p.FromString("" +
		"SecDataset test `\n123\n456\n`\n"); err != nil {
		t.Error(err)
	}
	ds := p.options.Datasets["test"]
	if len(ds) != 2 {
		t.Errorf("failed to add dataset, got %d records", len(ds))
	}
	if ds[0] != "123" || ds[1] != "456" {
		t.Error("failed to add dataset")
	}
}
