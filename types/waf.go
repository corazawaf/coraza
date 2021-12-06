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

package types

import (
	"fmt"
	"strings"
)

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
	return -1, fmt.Errorf("invalid rule engine status: %s", re)
}

// String returns the string representation of the
// rule engine status
func (re RuleEngineStatus) String() string {
	switch re {
	case RuleEngineOn:
		return "on"
	case RuleEngineDetectionOnly:
		return "DetectionOnly"
	case RuleEngineOff:
		return "off"
	}
	return "unknown"
}

// RequestBodyLimitAction represents the action
// to take when the request body size exceeds
// the configured limit.
type RequestBodyLimitAction int

const (
	// RequestBodyLimitActionProcessPartial will process the request body
	// up to the limit and then reject the request
	RequestBodyLimitActionProcessPartial RequestBodyLimitAction = 0
	// RequestBodyLimitActionReject will reject the request in case
	// the request body size exceeds the configured limit
	RequestBodyLimitActionReject RequestBodyLimitAction = 1
)

// ParseRequestBodyLimitAction parses the request body limit action
func ParseRequestBodyLimitAction(rbla string) (RequestBodyLimitAction, error) {
	switch strings.ToLower(rbla) {
	case "processpartial":
		return RequestBodyLimitActionProcessPartial, nil
	case "reject":
		return RequestBodyLimitActionReject, nil
	}
	return -1, fmt.Errorf("invalid request body limit action: %s", rbla)
}

type auditLogPart byte

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
type AuditLogParts []auditLogPart

const (
	// AuditLogPartAuditLogHeader is the mandatory header part
	AuditLogPartAuditLogHeader auditLogPart = 'A'
	// AuditLogPartRequestHeaders is the request headers part
	AuditLogPartRequestHeaders auditLogPart = 'B'
	// AuditLogPartRequestBody is the request body part
	AuditLogPartRequestBody auditLogPart = 'C'
	// AuditLogPartIntermediaryResponseHeaders is the intermediary response headers part
	AuditLogPartIntermediaryResponseHeaders auditLogPart = 'D'
	// AuditLogPartIntermediaryResponseBody is the intermediary response body part
	AuditLogPartIntermediaryResponseBody auditLogPart = 'E'
	// AuditLogPartResponseHeaders is the final response headers part
	AuditLogPartResponseHeaders auditLogPart = 'F'
	// AuditLogPartResponseBody is the final response body part
	AuditLogPartResponseBody auditLogPart = 'G'
	// AuditLogPartAuditLogTrailer is the audit log trailer part
	AuditLogPartAuditLogTrailer auditLogPart = 'H'
	// AuditLogPartRequestBodyAlternative is the request body replaced part
	AuditLogPartRequestBodyAlternative auditLogPart = 'I'
	// AuditLogPartUploadedFiles is the uploaded files part
	AuditLogPartUploadedFiles auditLogPart = 'J'
	// AuditLogPartRulesMatched is the matched rules part
	AuditLogPartRulesMatched auditLogPart = 'K'
	// AuditLogPartFinalBoundary is the mandatory final boundary part
	AuditLogPartFinalBoundary auditLogPart = 'Z'
)

// Interruption is used to notify the Coraza implementation
// that the transaction must be disrupted, for example:
// if it := tx.Interruption; it != nil {
//	return show403()
//}
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
