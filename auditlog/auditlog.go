// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"github.com/corazawaf/coraza/v3/types"
)

// Log represents the main struct for audit log data
type Log struct {
	// Parts contains the parts of the audit log
	Parts types.AuditLogParts `json:"-"`

	// Transaction contains the transaction information
	Transaction Transaction `json:"transaction"`

	// Messages contains the triggered rules information
	Messages []Message `json:"messages,omitempty"`
}

// Transaction contains transaction specific
// information
type Transaction struct {
	Request  *TransactionRequest  `json:"request,omitempty"`
	Response *TransactionResponse `json:"response,omitempty"`
	Producer *TransactionProducer `json:"producer,omitempty"`
	// Timestamp "02/Jan/2006:15:04:20 -0700" format
	Timestamp string `json:"timestamp"`

	// Unique ID
	ID string `json:"id"`

	// Client IP Address string representation
	ClientIP string `json:"client_ip"`

	HostIP        string `json:"host_ip"`
	ServerID      string `json:"server_id"`
	UnixTimestamp int64  `json:"unix_timestamp"`

	ClientPort int `json:"client_port"`
	HostPort   int `json:"host_port"`
}

// TransactionResponse contains response specific
// information
type TransactionResponse struct {
	Headers  map[string][]string `json:"headers"`
	Protocol string              `json:"protocol"`
	Body     string              `json:"body"`
	Status   int                 `json:"status"`
}

// TransactionProducer contains producer specific
// information for debugging
type TransactionProducer struct {
	Connector  string   `json:"connector"`
	Version    string   `json:"version"`
	Server     string   `json:"server"`
	RuleEngine string   `json:"rule_engine"`
	Stopwatch  string   `json:"stopwatch"`
	Rulesets   []string `json:"rulesets"`
}

// TransactionRequest contains request specific
// information
type TransactionRequest struct {
	Method      string                    `json:"method"`
	Protocol    string                    `json:"protocol"`
	URI         string                    `json:"uri"`
	HTTPVersion string                    `json:"http_version"`
	Headers     map[string][]string       `json:"headers"`
	Body        string                    `json:"body"`
	Files       []TransactionRequestFiles `json:"files"`
}

// TransactionRequestFiles contains information
// for the uploaded files using multipart forms
type TransactionRequestFiles struct {
	Name string `json:"name"`
	Mime string `json:"mime"`
	Size int64  `json:"size"`
}

// Message contains information about the triggered
// rules
type Message struct {
	Actionset string      `json:"actionset"`
	Message   string      `json:"message"`
	Data      MessageData `json:"data"`
}

// MessageData contains information about the triggered
// rules in detail
type MessageData struct {
	File     string             `json:"file"`
	Rev      string             `json:"rev"`
	Msg      string             `json:"msg"`
	Data     string             `json:"data"`
	Ver      string             `json:"ver"`
	Raw      string             `json:"raw"`
	Tags     []string           `json:"tags"`
	Line     int                `json:"line"`
	ID       int                `json:"id"`
	Severity types.RuleSeverity `json:"severity"`
	Maturity int                `json:"maturity"`
	Accuracy int                `json:"accuracy"`
}

// LEGACY FORMAT

// Main struct for audit log data
type logLegacy struct {

	// Section B or C
	Request *logLegacyRequest `json:"request,omitempty"`

	// Section J (File Uploads)
	// TBI

	// Section E and F
	Response *logLegacyResponse `json:"response,omitempty"`

	// Section H
	AuditData *logLegacyData `json:"audit_data,omitempty"`
	// Section A
	Transaction logLegacyTransaction `json:"transaction"`
}

type logLegacyTransaction struct {
	// Time format 03/Dec/2021:01:13:44.468137 +0000
	Time          string `json:"time"`
	TransactionID string `json:"transaction_id"`
	RemoteAddress string `json:"remote_address"`
	LocalAddress  string `json:"local_address"`
	RemotePort    int    `json:"remote_port"`
	LocalPort     int    `json:"local_port"`
}

type logLegacyRequest struct {
	// Headers should be a map of slices but in this case they are
	// joined by comma (,)
	Headers     map[string]string `json:"headers,omitempty"`
	RequestLine string            `json:"request_line"`
}

type logLegacyResponse struct {
	Headers  map[string]string `json:"headers"`
	Protocol string            `json:"protocol"`
	Status   int               `json:"status"`
}

type logLegacyData struct {
	Handler               string             `json:"handler"`
	Server                string             `json:"server"`
	EngineMode            string             `json:"engine_mode"`
	Messages              []string           `json:"messages"`
	ErrorMessages         []string           `json:"error_messages"`
	Producer              []string           `json:"producer"`
	Stopwatch             logLegacyStopwatch `json:"stopwatch"`
	ResponseBodyDechunked bool               `json:"response_body_dechunked"`
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
