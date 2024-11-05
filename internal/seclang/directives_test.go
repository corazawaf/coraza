// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
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
	w := corazawaf.NewWAF()
	p := NewParser(w)
	for _, rule := range rules {
		err := p.FromString(rule)
		if err != nil {
			t.Errorf("failed to set directive: %s", rule)
		}
	}
}

func TestSecRuleUpdateActionByID(t *testing.T) {
	waf := corazawaf.NewWAF()
	rule, err := ParseRule(RuleOptions{
		Data:         "REQUEST_URI \"^/test\" \"id:181,log\"",
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
	if err := directiveSecRuleUpdateActionByID(&DirectiveOptions{
		WAF:  waf,
		Opts: "181 \"nolog\"",
	}); err != nil {
		t.Error(err)
	}

}

func TestSecRuleUpdateTargetByID(t *testing.T) {
	waf := corazawaf.NewWAF()
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
		WAF:  waf,
		Opts: "181 \"REQUEST_HEADERS\"",
	}); err != nil {
		t.Error(err)
	}

}

func TestInvalidBooleanForDirectives(t *testing.T) {
	waf := corazawaf.NewWAF()
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
	waf := corazawaf.NewWAF()
	p := NewParser(waf)
	if err := p.FromString("secignorerulecompilationerrors On\n" + directives); err != nil {
		t.Error(err)
	}
	waf = corazawaf.NewWAF()
	p = NewParser(waf)
	if err := p.FromString(directives); err == nil {
		t.Error("failed to error on invalid rule")
	}
}

func TestSecDataset(t *testing.T) {
	waf := corazawaf.NewWAF()
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

var expectErrorOnDirective func(*corazawaf.WAF) bool = nil
var expectNoErrorOnDirective func(*corazawaf.WAF) bool = func(*corazawaf.WAF) bool { return true }

func TestDirectives(t *testing.T) {
	type directiveCase struct {
		opts  string
		check func(*corazawaf.WAF) bool
	}
	directiveCases := map[string][]directiveCase{
		"SecComponentSignature": {
			{"", expectErrorOnDirective},
			{"name", func(w *corazawaf.WAF) bool { return len(w.ComponentNames) == 1 }},
		},
		"SecMarker": {
			{"", expectErrorOnDirective},
			{"999", func(w *corazawaf.WAF) bool { return w.Rules.Count() == 1 }},
			{"MY_TEXT", func(w *corazawaf.WAF) bool { return w.Rules.Count() == 1 }},
		},
		"SecWebAppId": {
			{"", expectErrorOnDirective},
			{"test123", func(w *corazawaf.WAF) bool { return w.WebAppID == "test123" }},
		},
		"SecUploadKeepFiles": {
			{"", expectErrorOnDirective},
			{"Ox", expectErrorOnDirective},
			{"On", func(w *corazawaf.WAF) bool { return w.UploadKeepFiles }},
			{"Off", func(w *corazawaf.WAF) bool { return !w.UploadKeepFiles }},
		},
		"SecUploadFileMode": {
			{"", expectErrorOnDirective},
			{"888", expectErrorOnDirective},
			{"700", func(w *corazawaf.WAF) bool { return w.UploadFileMode == 0700 }},
		},
		"SecUploadFileLimit": {
			{"", expectErrorOnDirective},
			{"1000", func(w *corazawaf.WAF) bool { return w.UploadFileLimit == 1000 }},
		},
		"SecUploadDir": {
			{"", expectErrorOnDirective},
			{"/tmp-non-existing", expectErrorOnDirective},
			{os.TempDir(), func(w *corazawaf.WAF) bool { return w.UploadDir == os.TempDir() }},
		},
		"SecSensorId": {
			{"", expectErrorOnDirective},
			{"test", func(w *corazawaf.WAF) bool { return w.SensorID == "test" }},
		},
		"SecRuleEngine": {
			{"What?", expectErrorOnDirective},
			{"DetectionOnly", func(w *corazawaf.WAF) bool { return w.RuleEngine == types.RuleEngineDetectionOnly }},
			{"On", func(w *corazawaf.WAF) bool { return w.RuleEngine == types.RuleEngineOn }},
			{"Off", func(w *corazawaf.WAF) bool { return w.RuleEngine == types.RuleEngineOff }},
		},
		"SecAction": {
			{"", expectErrorOnDirective},
			{`"id:1,tag:test"`, func(w *corazawaf.WAF) bool { return w.Rules.Count() == 1 }},
		},
		"SecRuleRemoveByTag": {
			{"", expectErrorOnDirective},
			{"attack-sqli", expectNoErrorOnDirective},
		},
		"SecRuleRemoveByMsg": {
			{"", expectErrorOnDirective},
		},
		"SecRuleRemoveById": {
			{"", expectErrorOnDirective},
			{"a", expectErrorOnDirective},
			{"1-a", expectErrorOnDirective},
			{"a-2", expectErrorOnDirective},
			{"2-1", expectErrorOnDirective},
			{"-1", expectErrorOnDirective},
			{"-5--1", expectErrorOnDirective},
			{"5--1", expectErrorOnDirective},
			{"1", expectNoErrorOnDirective},
			{"1 2", expectNoErrorOnDirective},
			{"1 2 3-4", expectNoErrorOnDirective},
		},
		"SecRuleUpdateActionById": {
			{"", expectErrorOnDirective},
			{"a", expectErrorOnDirective},
			{"1-a", expectErrorOnDirective},
			{"a-2", expectErrorOnDirective},
			{"2-1", expectErrorOnDirective},
			{"1-a \"status:403\"", expectErrorOnDirective},
			{"a-2 \"status:403\"", expectErrorOnDirective},
			{"2-1 \"status:403\"", expectErrorOnDirective},
			{"-1 \"status:403\"", expectErrorOnDirective},
			{"1 2 3-4 \"status:403\"", expectNoErrorOnDirective},
			{"1 2 3-4 \"status:403,nolog\"", expectNoErrorOnDirective},
		},
		"SecRuleUpdateTargetById": {
			{"", expectErrorOnDirective},
			{"a", expectErrorOnDirective},
			{"1-a", expectErrorOnDirective},
			{"a-2", expectErrorOnDirective},
			{"2-1", expectErrorOnDirective},
			{"1-a \"ARGS:wp_post\"", expectErrorOnDirective},
			{"a-2 \"ARGS:wp_post\"", expectErrorOnDirective},
			{"2-1 \"ARGS:wp_post\"", expectErrorOnDirective},
			{"-1 \"ARGS:wp_post\"", expectErrorOnDirective},
			{"-5--1 \"ARGS:wp_post\"", expectErrorOnDirective},
			{"5--1 \"ARGS:wp_post\"", expectErrorOnDirective},
			// Variables has also to be provided to the directive
			{"1", expectErrorOnDirective},
			{"1 \"ARGS:wp_post\"", expectNoErrorOnDirective},
			{"7-7 \"ARGS:wp_post\"", expectNoErrorOnDirective},
			{"1 2 \"ARGS:wp_post\"", expectNoErrorOnDirective},
			{"1 2 3-4 \"ARGS:wp_post\"", expectNoErrorOnDirective},
			{"1 \"REQUEST_BODY|ARGS:wp_post\"", expectNoErrorOnDirective},
			{"1 2 3-4 \"ARGS:wp_post|RESPONSE_HEADERS\"", expectNoErrorOnDirective},
		},
		"SecRuleUpdateTargetByTag": {
			{"", expectErrorOnDirective},
			{"a", expectErrorOnDirective},
			{"tag-1 \"ARGS:wp_post\"", expectNoErrorOnDirective},
			{"tag-1 tag-2 \"ARGS:wp_post\"", expectErrorOnDirective}, // Multiple tags in line is not supported
			{"tag-2 \"ARGS:wp_post|RESPONSE_HEADERS|!REQUEST_BODY\"", expectNoErrorOnDirective},
		},
		"SecResponseBodyMimeTypesClear": {
			{"", func(w *corazawaf.WAF) bool { return len(w.ResponseBodyMimeTypes) == 0 }},
			{"x", expectErrorOnDirective},
		},
		"SecResponseBodyMimeType": {
			{"", expectErrorOnDirective},
			{"text/html", func(w *corazawaf.WAF) bool { return w.ResponseBodyMimeTypes[0] == "text/html" }},
		},
		"SecServerSignature": {
			{"", expectErrorOnDirective},
			{`"Microsoft-IIS/6.0"`, func(w *corazawaf.WAF) bool { return w.ServerSignature == "Microsoft-IIS/6.0" }},
		},
		"SecRequestBodyLimit": {
			{"", expectErrorOnDirective},
			{"x", expectErrorOnDirective},
			{"123", func(w *corazawaf.WAF) bool { return w.RequestBodyLimit == 123 }},
		},
		"SecResponseBodyLimit": {
			{"", expectErrorOnDirective},
			{"y", expectErrorOnDirective},
			{"123", func(w *corazawaf.WAF) bool { return w.ResponseBodyLimit == 123 }},
		},
		"SecRequestBodyInMemoryLimit": {
			{"", expectErrorOnDirective},
			{"z", expectErrorOnDirective},
			{"123", func(w *corazawaf.WAF) bool { return *(w.RequestBodyInMemoryLimit()) == 123 }},
		},
		"SecRequestBodyLimitAction": {
			{"", expectErrorOnDirective},
			{"What?", expectErrorOnDirective},
			{"Reject", func(w *corazawaf.WAF) bool { return w.RequestBodyLimitAction == types.BodyLimitActionReject }},
			{"ProcessPartial", func(w *corazawaf.WAF) bool { return w.RequestBodyLimitAction == types.BodyLimitActionProcessPartial }},
		},
		"SecRequestBodyAccess": {
			{"", expectErrorOnDirective},
			{"What?", expectErrorOnDirective},
			{"On", func(w *corazawaf.WAF) bool { return w.RequestBodyAccess }},
			{"Off", func(w *corazawaf.WAF) bool { return !w.RequestBodyAccess }},
		},
		"SecResponseBodyLimitAction": {
			{"", expectErrorOnDirective},
			{"What?", expectErrorOnDirective},
			{"Reject", func(w *corazawaf.WAF) bool { return w.ResponseBodyLimitAction == types.BodyLimitActionReject }},
			{"ProcessPartial", func(w *corazawaf.WAF) bool { return w.ResponseBodyLimitAction == types.BodyLimitActionProcessPartial }},
		},
		"SecResponseBodyAccess": {
			{"", expectErrorOnDirective},
			{"What?", expectErrorOnDirective},
			{"On", func(w *corazawaf.WAF) bool { return w.ResponseBodyAccess }},
			{"Off", func(w *corazawaf.WAF) bool { return !w.ResponseBodyAccess }},
		},
		"SecRemoteRulesFailAction": {
			{"", expectErrorOnDirective},
			{"What?", expectErrorOnDirective},
			{"Abort", func(w *corazawaf.WAF) bool { return w.AbortOnRemoteRulesFail }},
		},
		"SecDefaultAction": {
			{"", expectErrorOnDirective},
		},
		"SecAuditLog": {
			{"", expectErrorOnDirective},
		},
		"SecArgumentsLimit": {
			{"", expectErrorOnDirective},
			{"0", expectErrorOnDirective},
			{"10", func(waf *corazawaf.WAF) bool { return waf.ArgumentLimit == 10 }},
			// according to modsec docs SecArgumentsLimit 1000
			{"1000", func(waf *corazawaf.WAF) bool { return waf.ArgumentLimit == 1000 }},
		},
	}

	for name, dCases := range directiveCases {
		t.Run(name, func(t *testing.T) {
			for _, tCase := range dCases {
				d := directivesMap[strings.ToLower(name)]

				t.Run(tCase.opts, func(t *testing.T) {
					waf := corazawaf.NewWAF()

					err := d(&DirectiveOptions{
						Opts: tCase.opts,
						WAF:  waf,
					})

					if tCase.check == nil {
						if err == nil {
							t.Error("expected error")
						}
					} else {
						if err != nil {
							match, _ := regexp.MatchString(`rule "\d+" not found`, err.Error())
							// Logical errors are not checked by this test, therefore this specific pattern is allowed here
							if !match {
								// Syntax errors are checked
								t.Errorf("unexpected error: %s", err.Error())
							}
						}

						if !tCase.check(waf) {
							t.Errorf("check failed")
						}
					}
				})
			}
		})
	}
}
