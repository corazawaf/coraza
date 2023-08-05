// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugintypes

import (
	"io/fs"

	"github.com/corazawaf/coraza/v3/types"
)

// AuditLog represents the main struct for audit log data
type AuditLog interface {
	Parts() types.AuditLogParts
	Transaction() AuditLogTransaction
	Messages() []AuditLogMessage
}

// AuditLogTransaction contains transaction specific information
type AuditLogTransaction interface {
	Timestamp() string
	UnixTimestamp() int64
	ID() string
	ClientIP() string
	ClientPort() int
	HostIP() string
	HostPort() int
	ServerID() string
	Request() AuditLogTransactionRequest
	HasRequest() bool
	Response() AuditLogTransactionResponse
	HasResponse() bool
	Producer() AuditLogTransactionProducer
}

// AuditLogTransactionResponse contains response specific information
type AuditLogTransactionResponse interface {
	Protocol() string
	Status() int
	Headers() map[string][]string
	Body() string
}

// AuditLogTransactionProducer contains producer specific information
// for debugging
type AuditLogTransactionProducer interface {
	Connector() string
	Version() string
	Server() string
	RuleEngine() string
	Stopwatch() string
	Rulesets() []string
}

// AuditLogTransactionRequest contains request specific information
type AuditLogTransactionRequest interface {
	Method() string
	Protocol() string
	URI() string
	HTTPVersion() string
	Headers() map[string][]string
	Body() string
	Files() []AuditLogTransactionRequestFiles
}

// AuditLogTransactionRequestFiles contains information for the
// uploaded files using multipart forms
type AuditLogTransactionRequestFiles interface {
	Name() string
	Size() int64
	Mime() string
}

// AuditLogMessage contains information about the triggered rules
type AuditLogMessage interface {
	Actionset() string
	Message() string
	Data() AuditLogMessageData
}

// AuditLogMessageData contains information about the triggered rules
// in detail
type AuditLogMessageData interface {
	File() string
	Line() int
	ID() int
	Rev() string
	Msg() string
	Data() string
	Severity() types.RuleSeverity
	Ver() string
	Maturity() int
	Accuracy() int
	Tags() []string
	Raw() string
}

// AuditLogConfig is the configuration of a Writer.
type AuditLogConfig struct {
	// Target is the path to the file to write the raw audit log to.
	Target string

	// FileMode is the mode to use when creating File.
	FileMode fs.FileMode

	// Dir is the path to the directory to write formatted audit logs to.
	Dir string

	// DirMode is the mode to use when creating Dir.
	DirMode fs.FileMode

	// Formatter is the formatter to use when writing formatted audit logs.
	Formatter AuditLogFormatter
}

// AuditLogWriter is the interface for all log writers.
// It receives an auditlog and writes it to the output stream
// An output stream may be a file, a socket, an URL, etc
type AuditLogWriter interface {
	// Init the writer requires previous preparations
	Init(AuditLogConfig) error
	// Write the audit log to the output destination.
	// Using the Formatter is mandatory to generate a "readable" audit log
	// It is not sent as a bslice because some writers may require some Audit
	// metadata.
	Write(AuditLog) error
	// Close the writer if required
	Close() error
}

// AuditLogFormatter serializes an AuditLog into a byte slice.
// It is used to construct the formatted audit log.
type AuditLogFormatter interface {
	Format(AuditLog) ([]byte, error)
	MIME() string
}
