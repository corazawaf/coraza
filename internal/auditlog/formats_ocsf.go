// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package ocsflog implements a set of log formatters and writers
// for audit logging.
//
// The following log formats are supported:
//
// - JSON
// - Coraza
// - Native
//
// The following log writers are supported:
//
// - Serial
// - Concurrent
//
// More writers and formatters can be registered using the RegisterWriter and
// RegisterFormatter functions.
package auditlog

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/events/application"
	"github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/events/application/enums"
	"github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/objects"
	ocsf_object_enums "github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/objects/enums"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

type ocsfFormatter struct{}

func (f ocsfFormatter) getRequestArguments(al plugintypes.AuditLog) string {
	argString := &strings.Builder{}
	if al.Transaction().Request().Args() != nil {
		args := al.Transaction().Request().Args().FindAll()
		i := 1
		count := len(args)
		for _, arg := range al.Transaction().Request().Args().FindAll() {
			argString.WriteString(fmt.Sprintf("%s=%s", arg.Key(), arg.Value()))
			if i < count {
				argString.WriteString(",")
			}
			i++
		}
	}
	return argString.String()
}

func (f ocsfFormatter) getRequestHeaders(al plugintypes.AuditLog) []*objects.HttpHeader {
	requestHeaders := []*objects.HttpHeader{}
	for key, values := range al.Transaction().Request().Headers() {
		for _, value := range values {
			requestHeaders = append(requestHeaders, &objects.HttpHeader{
				Name:  key,
				Value: value,
			})
		}
	}
	return requestHeaders
}

func (f ocsfFormatter) getResponseHeaders(al plugintypes.AuditLog) []*objects.HttpHeader {
	responseHeaders := []*objects.HttpHeader{}
	for key, values := range al.Transaction().Response().Headers() {
		for _, value := range values {
			responseHeaders = append(responseHeaders, &objects.HttpHeader{
				Name:  key,
				Value: value,
			})
		}
	}
	return responseHeaders
}

func (f ocsfFormatter) getAffectedWebResources(al plugintypes.AuditLog) []*objects.WebResource {
	// Create an array of web Resources affected by this activity
	webResources := []*objects.WebResource{}
	webResources = append(webResources, &objects.WebResource{
		UrlString: al.Transaction().Request().URI(),
	})

	return webResources
}

// Returns an array of Enrichment objects containing the details of each message in AuditLog.Messages
func (f ocsfFormatter) getMatchDetails(al plugintypes.AuditLog) []*objects.Enrichment {
	matchDetails := []*objects.Enrichment{}

	for _, match := range al.Messages() {
		matchData, _ := json.Marshal(match.Data())
		matchDetails = append(matchDetails, &objects.Enrichment{
			Data:  string(matchData),
			Name:  match.Data().Msg(),
			Value: match.Data().Data(),
		})
	}

	return matchDetails
}

// Returns an array of Observable objects
func (f ocsfFormatter) getObservables(al plugintypes.AuditLog) []*objects.Observable {
	observables := []*objects.Observable{}

	if al.Transaction().ServerID() != "" {
		observables = append(observables, &objects.Observable{
			Name:   "ServerID",
			Type:   "ServerID",
			TypeId: ocsf_object_enums.OBSERVABLE_TYPE_ID_OBSERVABLE_TYPE_ID_OTHER,
			Value:  al.Transaction().ServerID(),
		})
	}

	for _, file := range al.Transaction().Request().Files() {
		observables = append(observables, &objects.Observable{
			Name:   file.Name(),
			Type:   "File Name",
			TypeId: 7,
			Value:  file.Name(),
		})
		observables = append(observables, &objects.Observable{
			Name:   file.Name(),
			Type:   "Size",
			TypeId: ocsf_object_enums.OBSERVABLE_TYPE_ID_OBSERVABLE_TYPE_ID_OTHER,
			Value:  fmt.Sprint(file.Size()),
		})
		observables = append(observables, &objects.Observable{
			Name:   file.Name(),
			Type:   "Mime",
			TypeId: ocsf_object_enums.OBSERVABLE_TYPE_ID_OBSERVABLE_TYPE_ID_OTHER,
			Value:  file.Mime(),
		})
	}

	return observables
}

func (f ocsfFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {

	// Populate the required fields for the WebRecourcesActivity
	webResourcesActivity := application.WebResourcesActivity{
		ActivityId:   enums.WEB_RESOURCES_ACTIVITY_ACTIVITY_ID_WEB_RESOURCES_ACTIVITY_ACTIVITY_ID_READ,
		ActivityName: "Read",
		CategoryName: "Application Activity",
		ClassName:    "Web Resources Activity",
		CategoryUid:  enums.WEB_RESOURCES_ACTIVITY_CATEGORY_UID_WEB_RESOURCES_ACTIVITY_CATEGORY_UID_APPLICATION_ACTIVITY,
		ClassUid:     enums.WEB_RESOURCES_ACTIVITY_CLASS_UID_WEB_RESOURCES_ACTIVITY_CLASS_UID_WEB_RESOURCES_ACTIVITY,
		Time:         al.Transaction().UnixTimestamp(),
		ActionId:     enums.WEB_RESOURCES_ACTIVITY_ACTION_ID_WEB_RESOURCES_ACTIVITY_ACTION_ID_DENIED,
		Metadata: &objects.Metadata{
			CorrelationUid: "",
			EventCode:      "",
			Uid:            al.Transaction().ID(),
			//Labels:         [2]string{"", ""},
			LogLevel: "",
			LogName:  "",
			//LogProvider: "OWASP Coraza Web Application Firewall",
			LogProvider: al.Transaction().Producer().Connector(),
			LogVersion:  al.Transaction().Producer().Version(),
			LoggedTime:  time.Now().UnixMicro(),
			Product: &objects.Product{
				VendorName: "OWASP Coraza Web Application Firewall",
			},
			Version: "1.2.0",
		},
		TypeUid:     enums.WEB_RESOURCES_ACTIVITY_TYPE_UID_WEB_RESOURCES_ACTIVITY_TYPE_UID_WEB_RESOURCES_ACTIVITY_READ,
		Enrichments: f.getMatchDetails(al),
		HttpRequest: &objects.HttpRequest{
			Version:     al.Transaction().Request().Protocol(),
			Args:        f.getRequestArguments(al),
			HttpMethod:  al.Transaction().Request().Method(),
			Uid:         al.Transaction().Request().UID(),
			Url:         &objects.Url{UrlString: al.Transaction().Request().URI()},
			HttpHeaders: f.getRequestHeaders(al),
			Length:      al.Transaction().Request().Length(),
		},
		HttpResponse: &objects.HttpResponse{
			Code:        int32(al.Transaction().Response().Status()),
			HttpHeaders: f.getResponseHeaders(al),
		},
		SrcEndpoint: &objects.NetworkEndpoint{
			Ip:   al.Transaction().ClientIP(),
			Port: int32(al.Transaction().ClientPort()),
		},
		DstEndpoint: &objects.NetworkEndpoint{
			Ip:   al.Transaction().HostIP(),
			Port: int32(al.Transaction().HostPort()),
		},
		WebResources: f.getAffectedWebResources(al),
	}

	userAgent := al.Transaction().Request().Headers()["user-agent"]
	if len(userAgent) > 0 {
		webResourcesActivity.HttpRequest.UserAgent = userAgent[0]
	}

	// Note: 'referer' is a misspelling of 'referrer' but was incorporated into the HTTP specification with this misspelling
	// see https://en.wikipedia.org/wiki/HTTP_referer
	referrer := al.Transaction().Request().Headers()["referer"]
	if len(referrer) > 0 {
		webResourcesActivity.HttpRequest.Referrer = referrer[0]
	}

	xForwardedFor := al.Transaction().Request().Headers()["x-forwarded-for"]
	if len(xForwardedFor) > 0 {
		webResourcesActivity.HttpRequest.XForwardedFor = xForwardedFor
	}

	if len(al.Messages()) > 0 {
		message := al.Messages()[0]
		webResourcesActivity.Message = message.Message()
	}

	_, offset := time.Now().Zone()
	webResourcesActivity.TimezoneOffset = int32(offset)

	// The WebResource Activity Severity ID is not to be confused by the Transaction severity.  The Transaction severity has to do with Coraza error/debug severity,
	// while WebResource Activity Severity is defined by OCSF to represent the severity of the security event.
	// For now, we're setting severityID to 'Other' and setting Severity to the Highest severity of the matched rules.
	// A future update should map/translate rule severity to OCSF severity if possible.
	highestSeverity, _ := types.ParseRuleSeverity(al.Transaction().HighestSeverity())
	webResourcesActivity.Severity = highestSeverity.String()
	webResourcesActivity.SeverityId = enums.WEB_RESOURCES_ACTIVITY_SEVERITY_ID_WEB_RESOURCES_ACTIVITY_SEVERITY_ID_OTHER

	webResourcesActivity.StartTime = al.Transaction().UnixTimestamp()
	webResourcesActivity.TypeName = "Read"

	webResourcesActivity.Observables = f.getObservables(al)

	// Not implemented
	// webResourcesActivity.Count = 0
	// webResourcesActivity.Duration = 0
	// webResourcesActivity.EndTime = 0
	// webResourcesActivity.RawData = ""
	// webResourcesActivity.Status = ""
	// webResourcesActivity.StatusCode = ""
	// webResourcesActivity.StatusDetail = ""
	// webResourcesActivity.StatusId = enums.WEB_RESOURCES_ACTIVITY_STATUS_ID_WEB_RESOURCES_ACTIVITY_STATUS_ID_UNKNOWN
	// webResourcesActivity.Tls = &objects.Tls{}
	// webResourcesActivity.WebResourcesResult =
	// webResourcesActivity.Unmapped = nil

	logJson, _ := json.Marshal(&webResourcesActivity)

	return logJson, nil
}

func (ocsfFormatter) MIME() string {
	return "application/json"
}

var (
	_ plugintypes.AuditLogFormatter = (*ocsfFormatter)(nil)
)
