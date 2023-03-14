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
)

// Coraza format
func jsonFormatter(al *Log) ([]byte, error) {
	jsdata, err := json.Marshal(al)
	if err != nil {
		return nil, err
	}
	return jsdata, nil
}

// Coraza legacy json format
func legacyJSONFormatter(al *Log) ([]byte, error) {
	reqHeaders := map[string]string{}
	for k, v := range al.Transaction.Request.Headers {
		reqHeaders[k] = strings.Join(v, ", ")
	}
	resHeaders := map[string]string{}
	for k, v := range al.Transaction.Response.Headers {
		resHeaders[k] = strings.Join(v, ", ")
	}
	var messages []string
	for _, m := range al.Messages {
		messages = append(messages, m.Message)
	}
	var producers []string
	if conn := al.Transaction.Producer.Connector; conn != "" {
		producers = append(producers, conn)
	}
	producers = append(producers, al.Transaction.Producer.Rulesets...)
	al2 := logLegacy{
		Transaction: logLegacyTransaction{
			Time:          al.Transaction.Timestamp,
			TransactionID: al.Transaction.ID,
			RemoteAddress: al.Transaction.ClientIP,
			RemotePort:    al.Transaction.ClientPort,
			LocalAddress:  al.Transaction.HostIP,
			LocalPort:     al.Transaction.HostPort,
		},
		Request: logLegacyRequest{
			RequestLine: fmt.Sprintf("%s %s %s", al.Transaction.Request.Method, al.Transaction.Request.URI, al.Transaction.Request.HTTPVersion),
			Headers:     reqHeaders,
		},
		Response: logLegacyResponse{
			Status:   al.Transaction.Response.Status,
			Protocol: al.Transaction.Response.Protocol,
			Headers:  resHeaders,
		},
		AuditData: logLegacyData{
			Stopwatch:  logLegacyStopwatch{},
			Messages:   messages,
			Producer:   producers,
			EngineMode: al.Transaction.Producer.RuleEngine,
		},
	}

	jsdata, err := json.Marshal(al2)
	if err != nil {
		return nil, err
	}
	return jsdata, nil
}

var (
	_ LogFormatter = jsonFormatter
	_ LogFormatter = legacyJSONFormatter
)
