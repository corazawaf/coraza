// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/events/application"
	"github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/events/application/enums"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
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

		// validate MIME type
		if f.MIME() != "application/json" {
			t.Errorf("failed to match ocsfFormatter MIME type, \ngot: %s\nexpected: %s", fmt.Sprint(f.MIME()), "application/json")
		}

		// validate Unix Timestamp
		if wra.Time != al.Transaction().UnixTimestamp() {
			t.Errorf("failed to match audit log Unix Timestamp, \ngot: %s\nexpected: %s", fmt.Sprint(wra.Time), fmt.Sprint(al.Transaction().UnixTimestamp()))
		}

		// validate transation interruption
		if al.Transaction().IsInterrupted() {
			if wra.Action != "Denied" {
				t.Errorf("failed to match audit log Action, \ngot: %s\nexpected: %s", wra.Action, "Denied")
			}

			if wra.ActionId != enums.WEB_RESOURCES_ACTIVITY_ACTION_ID_WEB_RESOURCES_ACTIVITY_ACTION_ID_DENIED {
				t.Errorf("failed to match audit log Action ID, \ngot: %s\nexpected: %s", wra.ActionId, enums.WEB_RESOURCES_ACTIVITY_ACTION_ID_WEB_RESOURCES_ACTIVITY_ACTION_ID_DENIED)
			}
		} else {
			if wra.Action != "Allowed" {
				t.Errorf("failed to match audit log Action, \ngot: %s\nexpected: %s", wra.Action, "Allowed")
			}

			if wra.ActionId != enums.WEB_RESOURCES_ACTIVITY_ACTION_ID_WEB_RESOURCES_ACTIVITY_ACTION_ID_ALLOWED {
				t.Errorf("failed to match audit log Action ID, \ngot: %s\nexpected: %s", wra.ActionId, enums.WEB_RESOURCES_ACTIVITY_ACTION_ID_WEB_RESOURCES_ACTIVITY_ACTION_ID_ALLOWED)
			}
		}

		// validate Server ID
		for _, observable := range wra.Observables {
			if observable.Name == "ServerID" {
				if observable.Value != al.Transaction().ServerID() {
					t.Errorf("failed to match audit log Server ID, \ngot: %s\nexpected: %s", observable.Value, al.Transaction().ServerID())
				}
			}
		}

		// validate transaction requests
		if al.Transaction().HasRequest() {
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
			// validate Request Files
			for _, file := range al.Transaction().Request().Files() {
				for _, observable := range wra.Observables {
					if observable.Name == file.Name() {
						if observable.Type == "File Name" {
							if file.Name() != observable.Value {
								t.Errorf("failed to match audit log Request File Name, \ngot: %s\nexpected: %s", observable.Value, file.Name())
							}
						}
						if observable.Type == "Mime" {
							if file.Mime() != observable.Value {
								t.Errorf("failed to match audit log Request File Mime, \ngot: %s\nexpected: %s", observable.Value, file.Mime())
							}
						}
						if observable.Type == "Size" {
							if fmt.Sprint(file.Size()) != observable.Value {
								t.Errorf("failed to match audit log Request File Size, \ngot: %s\nexpected: %s", observable.Value, fmt.Sprint(file.Size()))
							}
						}
					}
				}
			}

			// validate Request Protocol
			if wra.HttpRequest.Version != al.Transaction().Request().Protocol() {
				t.Errorf("failed to match audit log HTTP Request Protocol, \ngot: %s\nexpected: %s", wra.HttpRequest.Version, al.Transaction().Request().Protocol())
			}

			// validate Request Arguments
			if al.Transaction().Request().Args() != nil {
				for _, arg := range al.Transaction().Request().Args().FindAll() {
					if strings.Contains(wra.HttpRequest.Args, fmt.Sprintf("%s=%s", arg.Key(), arg.Value())) == false {
						t.Errorf("failed to match audit log Request arguments, \n%s not found in: %s", fmt.Sprintf("%s=%s", arg.Key(), arg.Value()), wra.HttpRequest.Args)
					}
				}
			}

			// validate Request UID
			if wra.HttpRequest.Uid != al.Transaction().ID() {
				t.Errorf("failed to match audit log HTTP Request UID, \ngot: %s\nexpected: %s", wra.HttpRequest.Uid, al.Transaction().ID())
			}

			// validate Request Length
			if wra.HttpRequest.Length != al.Transaction().Request().Length() {
				t.Errorf("failed to match audit log HTTP Request Length, \ngot: %d\nexpected: %d", wra.HttpRequest.Length, al.Transaction().Request().Length())
			}
		}

		if al.Transaction().HasResponse() {
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

	// Test case for "normal" / "typical" transaction
	getArgs := collections.NewMap(variables.ArgsGet)
	postArgs := collections.NewMap(variables.ArgsPost)
	pathArgs := collections.NewMap(variables.ArgsPath)
	args := collections.NewConcatKeyed(variables.Args, getArgs, postArgs, pathArgs)
	getArgs.Add("qkey", "qvalue")
	postArgs.Add("pkey", "pvalue")
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
			IsInterrupted_: true,
			Request_: &TransactionRequest{
				URI_:    "/test.php?qkey=qvalue",
				Method_: "GET",
				Headers_: map[string][]string{
					"host": {
						"test.coraza.null",
					},
				},
				Body_:     "pkey=pvalue",
				Protocol_: "HTTP/1.1",
				Args_:     args,
				Length_:   112345,
				Files_: []plugintypes.AuditLogTransactionRequestFiles{
					&TransactionRequestFiles{
						Name_: "dummyfile.txt",
						Mime_: "text/plain",
						Size_: 12345,
					},
				},
			},
			Response_: &TransactionResponse{
				Status_: 200,
				Headers_: map[string][]string{
					"connection": {
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

	// Test case for abnormal transaction (all empty values, no arguments)
	getArgs = collections.NewMap(variables.ArgsGet)
	postArgs = collections.NewMap(variables.ArgsPost)
	pathArgs = collections.NewMap(variables.ArgsPath)
	args = collections.NewConcatKeyed(variables.Args, getArgs, postArgs, pathArgs)
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
			Timestamp_:     "",
			UnixTimestamp_: 0,
			ID_:            "",
			IsInterrupted_: true,
			ServerID_:      "someServer",
			Request_: &TransactionRequest{
				URI_:    "",
				Method_: "",
				Headers_: map[string][]string{
					"host": {
						"",
					},
					"accept": {
						"",
					},
					"accept-encoding": {
						"",
					},
					"accept-language": {
						"",
					},
					"cache-control": {
						"",
					},
					"connection": {
						"",
					},
					"upgrade-insecure-requests": {
						"",
					},
					"user-agent": {
						"",
					},
					"x-forwarded-for": {
						"",
					},
					"referer": {
						"",
					},
				},
				Body_:     "",
				Protocol_: "",
				Args_:     args,
				Length_:   0,
			},
			Response_: &TransactionResponse{
				Status_: 200,
				Headers_: map[string][]string{
					"connection": {
						"",
					},
					"content-type": {
						"",
					},
					"referrer-policy": {
						"",
					},
					"strict-transport-security": {
						"",
					},
					"transfer-encoding": {
						"",
					},
					"referer": {
						"",
					},
				},
				Body_: "",
			},
			Producer_: &TransactionProducer{
				Connector_: "",
				Version_:   "",
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

	// Test case for abnormal transaction (all empty values, no arguments, no reponse)
	getArgs = collections.NewMap(variables.ArgsGet)
	postArgs = collections.NewMap(variables.ArgsPost)
	pathArgs = collections.NewMap(variables.ArgsPath)
	args = collections.NewConcatKeyed(variables.Args, getArgs, postArgs, pathArgs)
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
			Timestamp_:     "",
			UnixTimestamp_: 0,
			ID_:            "",
			IsInterrupted_: true,
			Request_: &TransactionRequest{
				URI_:    "",
				Method_: "",
				Headers_: map[string][]string{
					"host": {
						"",
					},
					"accept": {
						"",
					},
					"accept-encoding": {
						"",
					},
					"accept-language": {
						"",
					},
					"cache-control": {
						"",
					},
					"connection": {
						"",
					},
					"upgrade-insecure-requests": {
						"",
					},
					"user-agent": {
						"",
					},
					"x-forwarded-for": {
						"",
					},
					"referer": {
						"",
					},
				},
				Body_:     "",
				Protocol_: "",
				Args_:     args,
			},
			Producer_: &TransactionProducer{
				Connector_: "",
				Version_:   "",
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
