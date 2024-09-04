// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/events/application"
)

func TestOCSFFormatter(t *testing.T) {
	for _, al := range createAuditLogs() {
		f := &ocsfFormatter{}
		data, err := f.Format(al)
		if err != nil {
			t.Error(err)
		}
		if !strings.Contains(f.MIME(), "json") {
			t.Errorf("failed to match MIME, expected json and got %s", f.MIME())
		}

		var wra application.WebResourcesActivity
		if err := json.Unmarshal(data, &wra); err != nil {
			t.Error(err)
		}

		// validate Unix Timestamp
		if wra.Time != al.Transaction().UnixTimestamp() {
			t.Errorf("failed to match audit log Unix Timestamp, \ngot: %s\nexpected: %s", fmt.Sprint(wra.Time), fmt.Sprint(al.Transaction().UnixTimestamp()))
		}
		// validate transaction ID
		if wra.Metadata.Uid != al.Transaction().ID() {
			t.Errorf("failed to match audit log data, \ngot: %s\nexpected: %s", wra.Metadata.Uid, al.Transaction().ID())
		}
		// validate Request URI
		if wra.HttpRequest.Url.UrlString != al.Transaction().Request().URI() {
			t.Errorf("failed to match audit log URI, \ngot: %s\nexpected: %s", wra.HttpRequest.Url.UrlString, al.Transaction().Request().URI())
		}
		// validate Request Method
		if wra.HttpRequest.HttpMethod != al.Transaction().Request().Method() {
			t.Errorf("failed to match audit log HTTP Request Method, \ngot: %s\nexpected: %s", wra.HttpRequest.HttpMethod, al.Transaction().Request().Method())
		}
		// validate Request Headers
		for _, header := range wra.HttpRequest.HttpHeaders {
			if header.Value != al.Transaction().Request().Headers()[header.Name][0] {
				t.Errorf("failed to match audit log Request Header, \ngot: %s\nexpected: %s", header.Value, al.Transaction().Request().Headers()[header.Name][0])
			}
		}
		// validate Request Protocol
		if wra.HttpRequest.Version != al.Transaction().Request().Protocol() {
			t.Errorf("failed to match audit log HTTP Request Protocol, \ngot: %s\nexpected: %s", wra.HttpRequest.Version, al.Transaction().Request().Protocol())
		}
		// validate Response Status
		if int(wra.HttpResponse.Code) != al.Transaction().Response().Status() {
			t.Errorf("failed to match audit log HTTP Response Status, \ngot: %s\nexpected: %s", fmt.Sprint(wra.HttpResponse.Code), fmt.Sprint(al.Transaction().Response().Status()))
		}
		// validate Response Headers
		for _, header := range wra.HttpResponse.HttpHeaders {
			if header.Value != al.Transaction().Response().Headers()[header.Name][0] {
				t.Errorf("failed to match audit log Response Header, \ngot: %s\nexpected: %s", header.Value, al.Transaction().Response().Headers()[header.Name][0])
			}
		}
		// validate Enrichments (Rule Matches)
		if wra.Enrichments[0].Name != al.Messages()[0].Data().Msg() {
			t.Errorf("failed to match audit log data, \ngot: %s\nexpected: %s", wra.Enrichments[0].Name, al.Messages()[0].Data().Msg())
		}
		// validate Schema
		// ocsf-schema-golang appears to have a bug and is not validating against the OCSF 1.2 Schema.
		// It would be nice to include this validation as part of the test suite, but for now it must be disabled until this bug is fixed.
		// if ocsfvalidate_1_2.Validate("web_resources_activity", data) != nil {
		// 	t.Errorf("failed to validate audit log schema, \ngot: %s\nexpected: %s", ocsfvalidate_1_2.Validate("web_resources_activity", data), "")
		// }
	}
}

func createAuditLogs() []*Log {

	transactionLogs := []*Log{}

	transactionLogs = append(transactionLogs, &Log{
		Parts_: []types.AuditLogPart{
			types.AuditLogPartRequestHeaders,
			types.AuditLogPartRequestBody,
			types.AuditLogPartIntermediaryResponseBody,
			types.AuditLogPartResponseHeaders,
			types.AuditLogPartAuditLogTrailer,
			types.AuditLogPartRulesMatched,
		},
		Transaction_: Transaction{
			Timestamp_:     "02/Jan/2006:15:04:20 -0700",
			UnixTimestamp_: 1136239460,
			ID_:            "123",
			Request_: &TransactionRequest{
				URI_:    "/test.php",
				Method_: "GET",
				Headers_: map[string][]string{
					"Host": {
						"test.coraza.null",
					},
				},
				Body_:     "some request body",
				Protocol_: "HTTP/1.1",
			},
			Response_: &TransactionResponse{
				Status_: 200,
				Headers_: map[string][]string{
					"Connection": {
						"close",
					},
				},
				Body_: "some response body",
			},
			Producer_: &TransactionProducer{
				Connector_: "some connector",
				Version_:   "1.2.3",
			},
		},
		Messages_: []plugintypes.AuditLogMessage{
			&Message{
				Message_: "some message",
				Data_: &MessageData{
					Msg_: "some message",
					Raw_: "SecAction \"id:100\"",
				},
			},
		},
	})

	transactionLogs = append(transactionLogs, &Log{
		Parts_: []types.AuditLogPart{
			types.AuditLogPartRequestHeaders,
			types.AuditLogPartRequestBody,
			types.AuditLogPartIntermediaryResponseBody,
			types.AuditLogPartResponseHeaders,
			types.AuditLogPartAuditLogTrailer,
			types.AuditLogPartRulesMatched,
		},
		Transaction_: Transaction{
			Timestamp_:     "08/Jul/2024:14:24:24 -0500",
			UnixTimestamp_: 1720466664,
			ID_:            "456",
			Request_: &TransactionRequest{
				URI_:    "/test.php?file=/etc/passwd",
				Method_: "GET",
				Headers_: map[string][]string{
					"Host": {
						"test.coraza.null",
					},
					"Accept": {
						"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
					},
					"Accept-Encoding": {
						"gzip, deflate, br, zstd",
					},
					"Accept-Language": {
						"en-US,en;q=0.9",
					},
					"Cache-Control": {
						"max-age=0",
					},
					"Connection": {
						"keep-alive",
					},
					"Upgrade-Insecure-Requests": {
						"1",
					},
					"User-Agent": {
						"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
					},
				},
				Body_:     "",
				Protocol_: "HTTP/1.1",
			},
			Response_: &TransactionResponse{
				Status_: 200,
				Headers_: map[string][]string{
					"Connection": {
						"close",
					},
					"Content-Type": {
						"text/html;charset=UTF-8",
					},
					"Referrer-Policy": {
						"no-referrer-when-downgrade",
					},
					"Strict-Transport-Security": {
						"max-age=63072000; includeSubDomains; preload;",
					},
					"Transfer-Encoding": {
						"chunked",
					},
				},
				Body_: "<html><head><head><body>some response body</body>",
			},
			Producer_: &TransactionProducer{
				Connector_: "some connector",
				Version_:   "1.2.3",
			},
		},
		Messages_: []plugintypes.AuditLogMessage{
			&Message{
				Message_: "some message",
				Data_: &MessageData{
					Msg_: "some message",
					Raw_: "SecAction \"id:100\"",
				},
			},
		},
	})

	return transactionLogs
}
