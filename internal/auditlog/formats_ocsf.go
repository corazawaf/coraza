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
	"time"

	"github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/events/application"
	"github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/events/application/enums"
	"github.com/valllabh/ocsf-schema-golang/ocsf/v1_2_0/objects"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

type ocsfFormatter struct{}

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

// Returns a OCSF Metadata object for the given in AuditLog
// func (f ocsfFormatter) getMetaData(al plugintypes.AuditLog) *objects.Metadata {
// 	metaData := &objects.Metadata{
// 		CorrelationUid: "",
// 		EventCode:      "",
// 		Uid:            al.Transaction().ID(),
// 		//Labels:         [2]string{"", ""},
// 		LogLevel:    "",
// 		LogName:     "",
// 		LogProvider: "OWASP Coraza Web Application Firewall",
// 		LogVersion:  "",
// 		LoggedTime:  time.Now().UnixMicro(),
// 		Product: &objects.Product{
// 			VendorName: "OWASP Coraza Web Application Firewall",
// 		},
// 		Version: "1.2.0",
// 	}

// 	return metaData
// }

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

func (f ocsfFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {

	// Populate the required fields for the WebRecourcesActivity
	webResourcesActivity := application.WebResourcesActivity{
		ActivityId:   enums.WEB_RESOURCES_ACTIVITY_ACTIVITY_ID_WEB_RESOURCES_ACTIVITY_ACTIVITY_ID_READ,
		ActivityName: enums.WEB_RESOURCES_ACTIVITY_ACTIVITY_ID_name[int32(enums.WEB_RESOURCES_ACTIVITY_ACTIVITY_ID_WEB_RESOURCES_ACTIVITY_ACTIVITY_ID_READ)],
		CategoryName: "Application Activity",
		ClassName:    "Web Resources Activity",
		CategoryUid:  0,
		ClassUid:     6001,
		Time:         al.Transaction().UnixTimestamp(),
		//Metadata:     f.getMetaData(al),
		Metadata: &objects.Metadata{
			CorrelationUid: "",
			EventCode:      "",
			Uid:            al.Transaction().ID(),
			//Labels:         [2]string{"", ""},
			LogLevel:    "",
			LogName:     "",
			LogProvider: "OWASP Coraza Web Application Firewall",
			LogVersion:  "",
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
			Args:        al.Transaction().Request().Args(),
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
	webResourcesActivity.TypeName = enums.WEB_RESOURCES_ACTIVITY_ACTIVITY_ID_name[int32(enums.WEB_RESOURCES_ACTIVITY_ACTIVITY_ID_WEB_RESOURCES_ACTIVITY_ACTIVITY_ID_READ)]

	// Not implemented
	// webResourcesActivity.Count = 0
	// webResourcesActivity.Duration = 0
	// webResourcesActivity.EndTime = 0
	// webResourcesActivity.Observables = &objects.Observable{}
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
