// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strings"
)

// Config is used to store the configuration of the WAF
// Internal configurations are not exported.
// This is used to connect directives with audit auditlog.
// A WAF instance will share it's Config object with the
// audit auditlog.
type Config map[string]interface{}

// Get returns the configuration value for the given key
// If the key is not found, it returns the default value
func (w Config) Get(key string, defaultValue interface{}) interface{} {
	if value, ok := w[key]; ok {
		return value
	}
	return defaultValue
}

// Set sets the configuration value for the given key
func (w Config) Set(key string, value interface{}) {
	w[key] = value
}

// AuditEngineStatus represents the functionality
// of the audit engine.
type AuditEngineStatus int

const (
	// AuditEngineOn will audit each auditable event
	AuditEngineOn AuditEngineStatus = iota
	// AuditEngineOff will not audit any event
	AuditEngineOff AuditEngineStatus = iota
	// AuditEngineRelevantOnly will audit only relevant events
	AuditEngineRelevantOnly AuditEngineStatus = iota
)

// ParseAuditEngineStatus parses the audit engine status
func ParseAuditEngineStatus(as string) (AuditEngineStatus, error) {
	switch strings.ToLower(as) {
	case "on":
		return AuditEngineOn, nil
	case "off":
		return AuditEngineOff, nil
	case "relevantonly":
		return AuditEngineRelevantOnly, nil
	}
	return -1, fmt.Errorf("invalid audit engine status: %s", as)
}

// RuleEngineStatus represents the functionality
// of the rule engine.
type RuleEngineStatus int

const (
	// RuleEngineOn will process each rule and may generate
	// disruptive actions
	RuleEngineOn RuleEngineStatus = iota
	// RuleEngineDetectionOnly will process each rule but won't
	// generate disruptive actions
	RuleEngineDetectionOnly RuleEngineStatus = iota
	// RuleEngineOff will not process any rule
	RuleEngineOff RuleEngineStatus = iota
)

// ParseRuleEngineStatus parses the rule engine status
func ParseRuleEngineStatus(re string) (RuleEngineStatus, error) {
	switch strings.ToLower(re) {
	case "on":
		return RuleEngineOn, nil
	case "detectiononly":
		return RuleEngineDetectionOnly, nil
	case "off":
		return RuleEngineOff, nil
	}
	return -1, fmt.Errorf("invalid rule engine status: %q", re)
}

// String returns the string representation of the
// rule engine status
func (re RuleEngineStatus) String() string {
	switch re {
	case RuleEngineOn:
		return "On"
	case RuleEngineDetectionOnly:
		return "DetectionOnly"
	case RuleEngineOff:
		return "Off"
	}
	return "unknown"
}

// BodyLimitAction represents the action to take when
// the body size exceeds the configured limit.
type BodyLimitAction int

const (
	// BodyLimitActionProcessPartial will process the body
	// up to the limit and then ignores the remaining body bytes
	BodyLimitActionProcessPartial BodyLimitAction = 0
	// BodyLimitActionReject will reject the connection in case
	// the body size exceeds the configured limit
	BodyLimitActionReject BodyLimitAction = 1
)

type AuditLogPart byte

// AuditLogParts represents the parts of the audit log
// A: Audit log header (mandatory).
// B: Request headers.
// C: Request body
// D: Reserved for intermediary response headers; not implemented yet.
// E: Intermediary response body (not implemented yet).
// F: Final response headers
// G: Reserved for the actual response body; not implemented yet.
// H: Audit log trailer.
// I: This part is a replacement for part C.
// J: This part contains information about the files uploaded using multipart/form-data encoding.
// K: This part contains a full list of every rule that matched (one per line)
// Z: Final boundary, signifies the end of the entry (mandatory).
type AuditLogParts []AuditLogPart

const (
	// AuditLogPartAuditLogHeader is the mandatory header part
	AuditLogPartAuditLogHeader AuditLogPart = 'A'
	// AuditLogPartRequestHeaders is the request headers part
	AuditLogPartRequestHeaders AuditLogPart = 'B'
	// AuditLogPartRequestBody is the request body part
	AuditLogPartRequestBody AuditLogPart = 'C'
	// AuditLogPartIntermediaryResponseHeaders is the intermediary response headers part
	AuditLogPartIntermediaryResponseHeaders AuditLogPart = 'D'
	// AuditLogPartIntermediaryResponseBody is the intermediary response body part
	AuditLogPartIntermediaryResponseBody AuditLogPart = 'E'
	// AuditLogPartResponseHeaders is the final response headers part
	AuditLogPartResponseHeaders AuditLogPart = 'F'
	// AuditLogPartResponseBody is the final response body part
	AuditLogPartResponseBody AuditLogPart = 'G'
	// AuditLogPartAuditLogTrailer is the audit log trailer part
	AuditLogPartAuditLogTrailer AuditLogPart = 'H'
	// AuditLogPartRequestBodyAlternative is the request body replaced part
	AuditLogPartRequestBodyAlternative AuditLogPart = 'I'
	// AuditLogPartUploadedFiles is the uploaded files part
	AuditLogPartUploadedFiles AuditLogPart = 'J'
	// AuditLogPartRulesMatched is the matched rules part
	AuditLogPartRulesMatched AuditLogPart = 'K'
	// AuditLogPartFinalBoundary is the mandatory final boundary part
	AuditLogPartFinalBoundary AuditLogPart = 'Z'
)

// Interruption is used to notify the Coraza implementation
// that the transaction must be disrupted, for example:
//
//	if it := tx.Interruption; it != nil {
//		return show403()
//	}
type Interruption struct {
	// Rule that caused the interruption
	RuleID int

	// drop, deny, redirect
	Action string

	// Force this status code
	Status int

	// Parameters used by proxy and redirect
	Data string
}

// BodyBufferOptions is used to feed a coraza.BodyBuffer with parameters
type BodyBufferOptions struct {
	// TmpPath is the path to store temporary files
	TmpPath string
	// MemoryLimit is the maximum amount of memory to be stored in memory
	// Once the limit is reached, the file will be stored on disk
	MemoryLimit int64
	// Limit is the overall maximum amount of memory to be buffered
	Limit int64
}
