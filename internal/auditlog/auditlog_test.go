// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

import (
	"slices"
	"testing"
)

func TestAuditLogUnmarshalInvalidJSON(t *testing.T) {
	// Improper JSON data (missing a closing '}')
	invalidSerializedLog := []byte(`{
		"transaction": {
			"id":
	}`)

	log := &Log{}

	// Verify a error is returned for invalidly formatted JSON data
	if err := log.UnmarshalJSON(invalidSerializedLog); err != nil {
		if err.Error() != "invalid character '}' looking for beginning of value" {
			t.Errorf("failed to match error message, \ngot: %s, \nexpected: %s", err, "invalid character '}' looking for beginning of value")
		}

	}
}

func TestAuditLogUnmarshalEmptyJSON(t *testing.T) {
	serializedLog := []byte(`{
		"transaction": {
		}
	}`)

	log := &Log{}

	// Validate proper results for nil values
	if err := log.UnmarshalJSON(serializedLog); err != nil {
		t.Error(err)
	}

	if want, have := "", log.Transaction().ID(); want != have {
		t.Errorf("failed to match transaction id, got: %s, expected: %s", have, want)
	}

	// Validate Transaction Request parameters
	if want, have := false, log.Transaction().HasRequest(); want != have {
		t.Errorf("failed to match transaction has request, got: %t, expected: %t", have, want)
	}

	if want, have := "", log.Transaction().Request().Method(); want != have {
		t.Errorf("failed to match transaction request method, got: %s, expected: %s", have, want)
	}

	if want, have := "", log.Transaction().Request().HTTPVersion(); want != have {
		t.Errorf("failed to match transaction request method, got: %s, expected: %s", have, want)
	}

	// Validate Transaction Response parameters
	if want, have := false, log.Transaction().HasResponse(); want != have {
		t.Errorf("failed to match transaction has response, got: %t, expected: %t", have, want)
	}

	if want, have := 0, log.Transaction().Response().Status(); want != have {
		t.Errorf("failed to match transaction has response, got: %d, expected: %d", have, want)
	}

	if want, have := "", log.Transaction().Response().Protocol(); want != have {
		t.Errorf("failed to match transaction has response, got: %s, expected: %s", have, want)
	}

	// Validate log messages
	if want, have := 0, len(log.Messages()); want != have {
		t.Errorf("failed to match messages length, got: %d, expected: %d", have, want)
	}

	// Validaate Transaction Producer parameters
	if want, have := "", log.Transaction().Producer().Connector(); want != have {
		t.Errorf("failed to match producer connector, got: %s, expected: %s", have, want)
	}

	if want, have := "", log.Transaction().Producer().Version(); want != have {
		t.Errorf("failed to match producer version, got: %s, expected: %s", have, want)
	}

	if want, have := "", log.Transaction().Producer().Server(); want != have {
		t.Errorf("failed to match producer server, got: %s, expected: %s", have, want)
	}

	if want, have := "", log.Transaction().Producer().RuleEngine(); want != have {
		t.Errorf("failed to match producer rule engine, got: %s, expected: %s", have, want)
	}

	if want, have := "", log.Transaction().Producer().Stopwatch(); want != have {
		t.Errorf("failed to match producer stopwatch, got: %s, expected: %s", have, want)
	}

	if have := log.Transaction().Producer().Rulesets(); nil != have {
		t.Errorf("failed to match producer ruleset, got: %s, expected: nil", have)
	}

	if want, have := false, log.Transaction_.HasResponse(); want != have {
		t.Errorf("failed to match transaction has response, got: %t, expected: %t", have, want)
	}

	if want, have := 0, log.Transaction().Response().Status(); want != have {
		t.Errorf("failed to match producer server, got: %d, expected: %d", have, want)
	}

	if want, have := false, log.Transaction_.HasRequest(); want != have {
		t.Errorf("failed to match transaction has request, got: %t, expected: %t", have, want)
	}
}

func TestAuditLogUnmarshalJSON(t *testing.T) {

	serializedLog := []byte(`{
		"transaction": {
			"id": "abc123",
			"producer": {
				"connector": "c",
				"version": "d",
				"server": "e",
				"rule_engine": "f",
				"stopwatch": "g",
				"rulesets": [
					"h",
					"i"
				]
			},
			"request": {
				"method": "",
				"protocol": "",
				"uri": "",
				"http_version": "",
				"body": "",
				"length": 123,
				"uid": "",
				"headers":{
					"request_header_key": [
						"request_header_value"
					]
				}
					
			},
			"response": {
				"status": 200,
				"protocol": "p",
				"body": "b",
				"headers":{
					"response_header_key": [
						"response_header_value"
					]
				}
			}
		},
		"messages": [
			{
				"actionset": "a",
				"message": "b",
				"data": {
					"file": "/etc/coraza-spoa/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
					"line": 4468,
					"id": 930130,
					"rev": "1.3",
					"msg": "Restricted File Access Attempt",
					"data": "Matched Data: /.git/ found within REQUEST_FILENAME: /.git/config",
					"severity": 2,
					"ver": "OWASP_CRS/4.4.0-dev",
					"maturity": 3,
					"accuracy": 8,
					"tags": [
						"application-multi",
						"language-multi",
						"platform-multi",
						"attack-lfi",
						"paranoia-level/1",
						"OWASP_CRS",
						"capec/1000/255/153/126",
						"PCI/6.5.4"
					],
					"raw": "SecRule REQUEST_FILENAME \"@pmFromFile restricted-files.data\" \"id: 930130,phase: 1,block,capture,t:none,t:utf8toUnicode,t:urlDecodeUni,t:normalizePathWin,msg:\"Restricted File Access Attempt\",logdata:\"Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}\",tag:\"application-multi\",tag:\"language-multi\",tag:\"platform-multi\",tag:\"attack-lfi\",tag:\"paranoia-level/1\",tag:\"OWASP_CRS\",tag:\"capec/1000/255/153/126\",tag:\"PCI/6.5.4\",ver:\"OWASP_CRS/4.4.0-dev\",severity:\"CRITICAL\",setvar:\"tx.lfi_score=+%{tx.critical_anomaly_score}\",setvar:\"tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}\"\""
				}
			}
		]
	}`)

	log := &Log{}
	if err := log.UnmarshalJSON(serializedLog); err != nil {
		t.Error(err)
	}

	if want, have := "abc123", log.Transaction().ID(); want != have {
		t.Errorf("failed to match transaction id, got: %s, expected: %s", have, want)
	}

	// Validate Transaction Request parameters
	if want, have := true, log.Transaction().HasRequest(); want != have {
		t.Errorf("failed to match transaction has request, got: %t, expected: %t", have, want)
	}

	if want, have := "", log.Transaction().Request().Method(); want != have {
		t.Errorf("failed to match transaction request method, got: %s, expected: %s", have, want)
	}

	if want, have := "request_header_value", log.Transaction().Request().Headers()["request_header_key"]; !slices.Contains(have, want) {
		t.Errorf("failed to match message data tags, expected tag: %s not found in array", want)
	}

	// Validate Transaction Response parameters
	if want, have := true, log.Transaction().HasResponse(); want != have {
		t.Errorf("failed to match transaction has response, got: %t, expected: %t", have, want)
	}

	if want, have := 200, log.Transaction().Response().Status(); want != have {
		t.Errorf("failed to match transaction response status, got: %d, expected: %d", have, want)
	}

	if want, have := "p", log.Transaction().Response().Protocol(); want != have {
		t.Errorf("failed to match transaction response protocol, got: %s, expected: %s", have, want)
	}

	if want, have := "b", log.Transaction().Response().Body(); want != have {
		t.Errorf("failed to match transaction response body, got: %s, expected: %s", have, want)
	}

	if want, have := "response_header_value", log.Transaction().Response().Headers()["response_header_key"]; !slices.Contains(have, want) {
		t.Errorf("failed to match transaction response header response_header_key, expected value: %s not found in array", want)
	}

	// Validate log messages
	if want, have := 1, len(log.Messages()); want != have {
		t.Errorf("failed to match messages length, got: %d, expected: %d", have, want)
	}

	if want, have := "a", log.Messages()[0].Actionset(); want != have {
		t.Errorf("failed to match actionset, got: %s, expected: %s", have, want)
	}

	if want, have := "b", log.Messages()[0].Message(); want != have {
		t.Errorf("failed to match message, got: %s, expected: %s", have, want)
	}

	if want, have := "/etc/coraza-spoa/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf", log.Messages()[0].Data().File(); want != have {
		t.Errorf("failed to match message data file, got: %s, expected: %s", have, want)
	}

	if want, have := 4468, log.Messages()[0].Data().Line(); want != have {
		t.Errorf("failed to match message data line, got: %d, expected: %d", have, want)
	}

	if want, have := 930130, log.Messages()[0].Data().ID(); want != have {
		t.Errorf("failed to match message data id, got: %d, expected: %d", have, want)
	}

	if want, have := "1.3", log.Messages()[0].Data().Rev(); want != have {
		t.Errorf("failed to match message data rev, got: %s, expected: %s", have, want)
	}

	if want, have := "Restricted File Access Attempt", log.Messages()[0].Data().Msg(); want != have {
		t.Errorf("failed to match message data msg, got: %s, expected: %s", have, want)
	}

	if want, have := "Matched Data: /.git/ found within REQUEST_FILENAME: /.git/config", log.Messages()[0].Data().Data(); want != have {
		t.Errorf("failed to match message data data, got: %s, expected: %s", have, want)
	}

	if want, have := 2, log.Messages()[0].Data().Severity().Int(); want != have {
		t.Errorf("failed to match message data severity, got: %d, expected: %d", have, want)
	}

	if want, have := "OWASP_CRS/4.4.0-dev", log.Messages()[0].Data().Ver(); want != have {
		t.Errorf("failed to match message data ver, got: %s, expected: %s", have, want)
	}

	if want, have := 3, log.Messages()[0].Data().Maturity(); want != have {
		t.Errorf("failed to match message data maturity, got: %d, expected: %d", have, want)
	}

	if want, have := 8, log.Messages()[0].Data().Accuracy(); want != have {
		t.Errorf("failed to match message data accuracy, got: %d, expected: %d", have, want)
	}

	if want, have := "application-multi", log.Messages()[0].Data().Tags(); !slices.Contains(have, want) {
		t.Errorf("failed to match message data tags, expected tag: %s not found in array", want)
	}

	if want, have := "paranoia-level/1", log.Messages()[0].Data().Tags(); !slices.Contains(have, want) {
		t.Errorf("failed to match message data tags, expected tag: %s not found in array", want)
	}

	if want, have := "capec/1000/255/153/126", log.Messages()[0].Data().Tags(); !slices.Contains(have, want) {
		t.Errorf("failed to match message data tags, expected tag: %s not found in array", want)
	}

	if want, have := "PCI/6.5.4", log.Messages()[0].Data().Tags(); !slices.Contains(have, want) {
		t.Errorf("failed to match message data tags, expected tag: %s not found in array", want)
	}

	// Validate Transaction Producer parameters
	if want, have := "c", log.Transaction().Producer().Connector(); want != have {
		t.Errorf("failed to match producer connector, got: %s, expected: %s", have, want)
	}

	if want, have := "d", log.Transaction().Producer().Version(); want != have {
		t.Errorf("failed to match producer version, got: %s, expected: %s", have, want)
	}

	if want, have := "e", log.Transaction().Producer().Server(); want != have {
		t.Errorf("failed to match producer server, got: %s, expected: %s", have, want)
	}

	if want, have := "f", log.Transaction().Producer().RuleEngine(); want != have {
		t.Errorf("failed to match producer rule engine, got: %s, expected: %s", have, want)
	}

	if want, have := "g", log.Transaction().Producer().Stopwatch(); want != have {
		t.Errorf("failed to match producer stopwatch, got: %s, expected: %s", have, want)
	}

	if want, have := "h", log.Transaction().Producer().Rulesets(); !slices.Contains(have, want) {
		t.Errorf("failed to match transaction producer rulesets, expected tag: %s not found in array", want)
	}

	if want, have := "i", log.Transaction().Producer().Rulesets(); !slices.Contains(have, want) {
		t.Errorf("failed to match transaction producer rulesets, expected tag: %s not found in array", want)
	}

}
