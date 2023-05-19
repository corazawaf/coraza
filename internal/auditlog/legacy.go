// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

// LEGACY FORMAT

// Main struct for audit log data
type logLegacy struct {
	// Section A
	Transaction logLegacyTransaction `json:"transaction"`

	// Section B or C
	Request *logLegacyRequest `json:"request,omitempty"`

	// Section J (File Uploads)
	// TBI

	// Section E and F
	Response *logLegacyResponse `json:"response,omitempty"`

	// Section H
	AuditData *logLegacyData `json:"audit_data,omitempty"`
}

type logLegacyTransaction struct {
	// Time format 03/Dec/2021:01:13:44.468137 +0000
	Time          string `json:"time"`
	TransactionID string `json:"transaction_id"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
	LocalAddress  string `json:"local_address"`
	LocalPort     int    `json:"local_port"`
}

type logLegacyRequest struct {
	RequestLine string `json:"request_line"`
	// Headers should be a map of slices but in this case they are
	// joined by comma (,)
	Headers map[string]string `json:"headers,omitempty"`
}

type logLegacyResponse struct {
	Status   int               `json:"status"`
	Protocol string            `json:"protocol"`
	Headers  map[string]string `json:"headers"`
}

type logLegacyData struct {
	Messages              []string           `json:"messages"`
	ErrorMessages         []string           `json:"error_messages"`
	Handler               string             `json:"handler"`
	Stopwatch             logLegacyStopwatch `json:"stopwatch"`
	ResponseBodyDechunked bool               `json:"response_body_dechunked"`
	Producer              []string           `json:"producer"`
	Server                string             `json:"server"`
	EngineMode            string             `json:"engine_mode"`
}

type logLegacyStopwatch struct {
	Combined int64 // Combined processing time
	P1       int64 // Processing time for the Request Headers phase
	P2       int64 // Processing time for the Request Body phase
	P3       int64 // Processing time for the Response Headers phase
	P4       int64 // Processing time for the Response Body phase
	P5       int64 // Processing time for the Logging phase
	Sr       int64 // Time spent reading from persistent storage
	Sw       int64 // Time spent writing to persistent storage
	L        int64 // Time spent on audit logging
	Gc       int64 // Time spent on garbage collection
}
