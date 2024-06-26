// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/events/application"
)

func TestOCSFFormatter(t *testing.T) {
	al := createAuditLog()
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
	if wra.HttpRequest.HttpHeaders[0].Value != al.Transaction().Request().Headers()["some"][0] {
		t.Errorf("failed to match audit log Request Header, \ngot: %s\nexpected: %s", wra.HttpRequest.HttpHeaders[0].Name, al.Transaction().Request().Headers()["some"][0])
	}
	// validate Request Protocol
	if wra.HttpRequest.Version != al.Transaction().Request().Protocol() {
		t.Errorf("failed to match audit log HTTP Request Protocol, \ngot: %s\nexpected: %s", wra.HttpRequest.Version, al.Transaction().Request().Protocol())
	}
	// validate Response Status
	if int(wra.HttpResponse.Code) != al.Transaction().Response().Status() {
		t.Errorf("failed to match audit log HTTP Response Status, \ngot: %s\nexpected: %s", wra.HttpRequest.HttpMethod, al.Transaction().Request().Method())
	}
	// validate Response Headers
	if wra.HttpRequest.HttpHeaders[0].Value != al.Transaction().Request().Headers()["some"][0] {
		t.Errorf("failed to match audit log Response Header, \ngot: %s\nexpected: %s", wra.HttpRequest.HttpHeaders[0].Name, al.Transaction().Request().Headers()["some"][0])
	}
	// validate Enrichments (Rule Matches)
	if wra.Enrichments[0].Name != al.Messages()[0].Data().Msg() {
		t.Errorf("failed to match audit log data, \ngot: %s\nexpected: %s", wra.Enrichments[0].Name, al.Messages()[0].Data().Msg())
	}

}
