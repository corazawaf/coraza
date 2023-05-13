// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// JSON auditlog not supported on TinyGo yet.
//go:build !tinygo
// +build !tinygo

package auditlog

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Coraza format
func jsonFormatter(al plugintypes.AuditLog) ([]byte, error) {
	jsdata, err := json.Marshal(al)
	if err != nil {
		return nil, err
	}
	return jsdata, nil
}

// Coraza legacy json format
func legacyJSONFormatter(al plugintypes.AuditLog) ([]byte, error) {
	al2 := logLegacy{
		Transaction: logLegacyTransaction{
			Time:          al.Transaction().Timestamp(),
			TransactionID: al.Transaction().ID(),
			RemoteAddress: al.Transaction().ClientIP(),
			RemotePort:    al.Transaction().ClientPort(),
			LocalAddress:  al.Transaction().HostIP(),
			LocalPort:     al.Transaction().HostPort(),
		},
	}
	if al.Transaction().Request() != nil {
		reqHeaders := map[string]string{}
		for k, v := range al.Transaction().Request().Headers() {
			reqHeaders[k] = strings.Join(v, ", ")
		}
		al2.Request = &logLegacyRequest{
			RequestLine: fmt.Sprintf(
				"%s %s %s",
				al.Transaction().Request().Method(),
				al.Transaction().Request().URI(),
				al.Transaction().Request().HTTPVersion(),
			),
			Headers: reqHeaders,
		}
	}
	if al.Transaction().Response() != nil {
		resHeaders := map[string]string{}
		for k, v := range al.Transaction().Response().Headers() {
			resHeaders[k] = strings.Join(v, ", ")
		}
		al2.Response = &logLegacyResponse{
			Status:   al.Transaction().Response().Status(),
			Protocol: al.Transaction().Response().Protocol(),
			Headers:  resHeaders,
		}
	}

	if al.Transaction().Producer() != nil {
		var producers []string
		if conn := al.Transaction().Producer().Connector(); conn != "" {
			producers = append(producers, conn)
		}
		producers = append(producers, al.Transaction().Producer().Rulesets()...)
		al2.AuditData = &logLegacyData{
			Stopwatch:  logLegacyStopwatch{},
			Producer:   producers,
			EngineMode: al.Transaction().Producer().RuleEngine(),
		}
	}

	if len(al.Messages()) > 0 {
		if al2.AuditData == nil {
			al2.AuditData = &logLegacyData{}
		}
		for _, m := range al.Messages() {
			al2.AuditData.Messages = append(al2.AuditData.Messages, m.Message())
		}
	}

	jsdata, err := json.Marshal(al2)
	if err != nil {
		return nil, err
	}
	return jsdata, nil
}

var (
	_ plugintypes.AuditLogFormatter = jsonFormatter
	_ plugintypes.AuditLogFormatter = legacyJSONFormatter
)
