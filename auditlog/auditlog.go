// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"github.com/corazawaf/coraza/v3/types"
)

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

// Formatter is the interface for all log formatters
// A LogFormatter receives an auditlog and generates "readable" audit log
type Formatter = func(al *AuditLog) ([]byte, error)

// Writer is the interface for all log writers
// A LogWriter receives an auditlog and writes it to the output stream
// An output stream may be a file, a socket, an http request, etc
type Writer interface {
	// Init the writer requires previous preparations
	Init(types.Config) error
	// Write the audit log
	// Using the LogFormatter is mandatory to generate a "readable" audit log
	// It is not sent as a bslice because some writers may require some Audit
	// metadata.
	Write(*AuditLog) error
	// Close the writer if required
	Close() error
}
