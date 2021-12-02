// Copyright 2021 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loggers

import "github.com/jptosso/coraza-waf/v2/types"

// AuditLog represents the main struct for audit log data
type AuditLog struct {
	// Parts contains the parts of the audit log
	Parts types.AuditLogParts `json:"-"`

	// Transaction contains the transaction information
	Transaction AuditTransaction `json:"transaction"`

	// Messages contains the triggered rules information
	Messages []AuditMessage `json:"messages"`
}

// AuditTransaction contains transaction specific
// information
type AuditTransaction struct {
	// Timestamp "02/Jan/2006:15:04:20 -0700" format
	Timestamp     string `json:"timestamp"`
	UnixTimestamp int64  `json:"unix_timestamp"`

	// Unique ID
	ID string `json:"id"`

	// Client IP Address string representation
	ClientIP string `json:"client_ip"`

	ClientPort int                      `json:"client_port"`
	HostIP     string                   `json:"host_ip"`
	HostPort   int                      `json:"host_port"`
	ServerID   string                   `json:"server_id"`
	Request    AuditTransactionRequest  `json:"request"`
	Response   AuditTransactionResponse `json:"response"`
	Producer   AuditTransactionProducer `json:"producer"`
}

// AuditTransactionResponse contains response specific
// information
type AuditTransactionResponse struct {
	Protocol string              `json:"protocol"`
	Status   int                 `json:"status"`
	Headers  map[string][]string `json:"headers"`
	Body     string              `json:"body"`
}

// AuditTransactionProducer contains producer specific
// information for debugging
type AuditTransactionProducer struct {
	Connector  string   `json:"connector"`
	Version    string   `json:"version"`
	Server     string   `json:"server"`
	RuleEngine string   `json:"rule_engine"`
	Stopwatch  string   `json:"stopwatch"`
	Rulesets   []string `json:"rulesets"`
}

// AuditTransactionRequest contains request specific
// information
type AuditTransactionRequest struct {
	Method      string                         `json:"method"`
	Protocol    string                         `json:"protocol"`
	URI         string                         `json:"uri"`
	HTTPVersion string                         `json:"http_version"`
	Headers     map[string][]string            `json:"headers"`
	Body        string                         `json:"body"`
	Files       []AuditTransactionRequestFiles `json:"files"`
}

// AuditTransactionRequestFiles contains information
// for the uploaded files using multipart forms
type AuditTransactionRequestFiles struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Mime string `json:"mime"`
}

// AuditMessage contains information about the triggered
// rules
type AuditMessage struct {
	Actionset string           `json:"actionset"`
	Message   string           `json:"message"`
	Data      AuditMessageData `json:"data"`
}

// AuditMessageData contains information about the triggered
// rules in detail
type AuditMessageData struct {
	File     string             `json:"file"`
	Line     int                `json:"line"`
	ID       int                `json:"id"`
	Rev      string             `json:"rev"`
	Msg      string             `json:"msg"`
	Data     string             `json:"data"`
	Severity types.RuleSeverity `json:"severity"`
	Ver      string             `json:"ver"`
	Maturity int                `json:"maturity"`
	Accuracy int                `json:"accuracy"`
	Tags     []string           `json:"tags"`
	Raw      string             `json:"raw"`
}

// LEGACY FORMAT

// Main struct for audit log data
type auditLogLegacy struct {
	// Section A
	Transaction auditLogLegacyTransaction `json:"transaction"`

	// Section B or C
	Request auditLogLegacyRequest `json:"request"`

	// Section J (File Uploads)
	// TBI

	// Section E and F
	Response auditLogLegacyResponse `json:"response"`

	// Section H
	AuditData auditLogLegacyData `json:"audit_data"`
}

type auditLogLegacyTransaction struct {
	Time          string
	TransactionID string
	RemoteAddress string
	RemotePort    int
	LocalAddress  string
	LocalPort     int
}

type auditLogLegacyRequest struct {
	RequestLine string
	Headers     map[string]string
}

type auditLogLegacyResponse struct {
	Status   int
	Protocol string
	Headers  map[string]string
}

type auditLogLegacyData struct {
	Messages              []string
	Handler               string
	Stopwatch             auditLogLegacyStopwatch
	ResponseBodyDechunked bool
	Producer              []string
	Server                string
	EngineMode            string
}

type auditLogLegacyStopwatch struct {
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
